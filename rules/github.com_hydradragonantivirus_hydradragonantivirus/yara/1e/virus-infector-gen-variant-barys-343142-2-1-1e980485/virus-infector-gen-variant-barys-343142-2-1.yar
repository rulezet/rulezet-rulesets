rule Virus_Infector_Gen_Variant_Barys_343142_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Gen.Variant.Barys.343142_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e723c350aeaa5923d0b84268a275f89246e657d5d0e5c34d44e82395a4eea227"

  strings:
    $s1 = "id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924# 2017/07/13-" ascii
    $s2 = ":39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=\"h" ascii
    $s3 = "id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924# 2017/07/13-" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}