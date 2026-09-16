rule Virus_Infector_Trojan_GenericKDZ_96072_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.GenericKDZ.96072_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aad3d3d24989c9aebb93247c28c7d0f06a60a1bdfe1fafdf9465c9da7923db79"

  strings:
    $s1 = ".org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://p" ascii
    $s2 = "s:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"http://w" ascii
    $s3 = "s:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"http://w" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}