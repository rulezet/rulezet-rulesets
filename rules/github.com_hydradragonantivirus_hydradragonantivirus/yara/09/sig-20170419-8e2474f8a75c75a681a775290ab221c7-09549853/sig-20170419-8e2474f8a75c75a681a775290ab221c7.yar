rule sig_20170419_8e2474f8a75c75a681a775290ab221c7 {
  meta:
    description = "datamaliciousorder - file 20170419_8e2474f8a75c75a681a775290ab221c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee5a47ac2e76e65291858f75c9f58eba157e5c130720120e6e278a89a2088b3c"

  strings:
    $s1 = "\"!val(un!scap!(\\\"var:20wsh:\"+" fullword ascii
    $s2 = "if (zdPSTLp.FolderExists(\"c\"+\":\\\\W\"+\"i\"+\"n\"+\"dOws\") == true) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}