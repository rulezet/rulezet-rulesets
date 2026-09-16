rule hc_volgmer__hiddencobra : malware windows
{
  meta:
    description = "Malformed User Agent"
  strings:
    $s = "Mozillar/"
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) 
    and $s
}