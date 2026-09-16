rule Trojan_Autorun_Trojan_Ransom_Doboc_A_9_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Ransom.Doboc.A_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b60967031f453e26d4f2b5dd7a4f9d76f1c10d240eaaa9b439040caad6b1e25"

  strings:
    $s1 = "}Iprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = "}Iprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}