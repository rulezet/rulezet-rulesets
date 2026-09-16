rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_33 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_33.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eea0185d1e6eba5e847880b20da94d2a8c5e9958e0b7f2698415a8e28ace6a10"

  strings:
    $s1 = "r': None, 'optimizer_scheduler': None, 'epochs': 100, 'plus_version': False, 'train_transform': Lambda()}, 'problem': <secml_mal" ascii
    $s2 = "r': None, 'optimizer_scheduler': None, 'epochs': 100, 'plus_version': False, 'train_transform': Lambda()}, 'problem': <secml_mal" ascii
    $s3 = "ware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f4b685abd60>, 'confidences_': [0.9998513460159302, 0.1652" ascii
    $s4 = "apperPhi object at 0x7f4b7caf0d00>, 'is_debug': False, " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}