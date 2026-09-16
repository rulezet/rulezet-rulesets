rule Virus_Infector_Win32_Expiro_Gen_7_169_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_169_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "902081d6db4fa0c17234eb60d74471440f7914c73cf52be7b6b02a56911b4d03"

  strings:
    $s1 = " xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"htt" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}