rule Virus_Hijack_Gen_Trojan_ShellObject_ryZ_ayMBdto_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ryZ@ayMBdto_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8208c636b3a17a37e80849cb1931543a259e7e18e50667fa89855ee853eec067"

  strings:
    $s1 = "lns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0" ascii
    $s2 = "c9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:R" ascii
    $s3 = "c9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:R" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}