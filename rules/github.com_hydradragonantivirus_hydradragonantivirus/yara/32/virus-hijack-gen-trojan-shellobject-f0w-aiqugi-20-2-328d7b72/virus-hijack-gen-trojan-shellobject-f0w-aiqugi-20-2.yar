rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_20_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_20_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf9906f609ca8c88645b2e199dd0f22c038954797f9d8bc51d381d12594a0608"

  strings:
    $s1 = "Couldn't remove file spec when attempting to verify the working directory path.  (%d)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}