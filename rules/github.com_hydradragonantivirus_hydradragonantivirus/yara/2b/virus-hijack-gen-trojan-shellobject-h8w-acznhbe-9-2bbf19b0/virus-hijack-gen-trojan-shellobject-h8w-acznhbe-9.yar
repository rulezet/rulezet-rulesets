rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193326d02000b8d47b75d46fc591d1e3d8fa11814629e104b13a3bc8f509d563"

  strings:
    $s1 = "Kpavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}