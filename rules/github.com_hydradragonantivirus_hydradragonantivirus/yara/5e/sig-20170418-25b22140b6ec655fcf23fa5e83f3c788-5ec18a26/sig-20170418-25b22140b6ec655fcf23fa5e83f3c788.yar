rule sig_20170418_25b22140b6ec655fcf23fa5e83f3c788 {
  meta:
    description = "datamaliciousorder - file 20170418_25b22140b6ec655fcf23fa5e83f3c788.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cbf2e426b17160da0545785df740c6d2785237a140cf1e2ba42545ab3890a8c"

  strings:
    $s1 = "\"!val(un!scap!(\\\"var:20wsh:20:3D:20n!w:\"+" fullword ascii
    $s2 = "\"Fold!rs:28\"+" fullword ascii
    $s3 = "if (IdnjRQiv.FolderExists(\"C\"+\":\\\\\"+\"wi\"+\"Nd\"+\"owS\") == true) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}