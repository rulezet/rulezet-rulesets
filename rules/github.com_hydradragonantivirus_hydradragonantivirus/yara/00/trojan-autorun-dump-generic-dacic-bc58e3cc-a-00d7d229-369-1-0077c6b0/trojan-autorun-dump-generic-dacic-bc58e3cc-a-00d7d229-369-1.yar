rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_369_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_369_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e501356175db705a8cf41ec28284bab2bd4fe541c96c2bea8638f6125217f8b0"

  strings:
    $s1 = "r': None, 'optimizer_scheduler': None, 'epochs': 100, 'plus_version': False, 'train_transform': Lambda()}, 'problem': <secml_mal" ascii
    $s2 = "r': None, 'optimizer_scheduler': None, 'epochs': 100, 'plus_version': False, 'train_transform': Lambda()}, 'problem': <secml_mal" ascii
    $s3 = "ware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f4b685abd60>, 'confidences_': [0.9998513460159302, 0.1652" ascii
    $s4 = "apperPhi object at 0x7f4b7caf0d00>, 'is_debug': False, " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}