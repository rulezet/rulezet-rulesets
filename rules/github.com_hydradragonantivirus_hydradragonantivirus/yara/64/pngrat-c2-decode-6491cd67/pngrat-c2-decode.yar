rule PNGRat_C2_Decode

{
  meta:
    Author    = "BB RSAIR"
    Date      = "15Jan2015"
    reference = "https://community.rsa.com/docs/DOC-30015"

  strings:
    $decode = { 8A 43 [0-1] B1 71 48 [0-4] C0 E0 04 41 B8 04 [0-3] 02 03 2A C1 }

  condition:
    $decode and uint16(0) == 0x5A4D
}