rule Virus_Infector_Win32_Backdoor_Agent_A_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Backdoor.Agent.A_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "037584f51aea34627aa99b48e7da2c680a6a21a53029a4578e8c8e889b0ccdeb"

  strings:
    $s1 = "id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924# 2017/07/13-" ascii
    $s2 = ":39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=\"h" ascii
    $s3 = "id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924# 2017/07/13-" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}