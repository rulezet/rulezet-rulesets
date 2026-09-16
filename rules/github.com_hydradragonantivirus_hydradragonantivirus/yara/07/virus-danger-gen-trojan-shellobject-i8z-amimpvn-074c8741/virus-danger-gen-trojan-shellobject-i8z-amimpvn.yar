rule Virus_Danger_Gen_Trojan_ShellObject_i8Z_amIMPvn {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.i8Z@amIMPvn.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "569c6abbfe7b90b995913e9ef3504d8d8818a7a5a22bb6a762aa1ab226d3853f"

  strings:
    $s1 = "\"policy, which might require you to return the software with the entire computer on which the software is" fullword ascii
    $s2 = "If you have a dispute with Oracle or if you wish to provide a notice under the `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}