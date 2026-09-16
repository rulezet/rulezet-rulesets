rule apt_blackwood_nspx30_plugin {
  meta:
    id             = "ef8e0d51-c78c-426b-8008-910e27546f23"
    version        = "1.0"
    description    = "Detects plugins of NSPX30 backdoor based on RTTI and rundll32 string"
    author         = "Sekoia.io"
    creation_date  = "2024-01-29"
    classification = "TLP:CLEAR"

  strings:
    $s1 = ".?AVCCabinet@@"
    $s2 = ".?AVCEncoder@@"
    $s3 = "rundll32.exe \"%hs\",#1" wide

  condition:
    uint16be(0) == 0x4d5a and filesize < 1MB and all of them
}