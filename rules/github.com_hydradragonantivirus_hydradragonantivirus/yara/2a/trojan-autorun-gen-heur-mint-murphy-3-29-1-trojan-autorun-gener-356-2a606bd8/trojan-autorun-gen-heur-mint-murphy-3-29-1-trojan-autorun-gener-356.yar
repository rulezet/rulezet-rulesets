import "pe"
rule _Trojan_Autorun_Gen_Heur_Mint_Murphy_3_29_1_Trojan_Autorun_Gener_356 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Gen.Heur.Mint.Murphy.3_29_1.vir, Trojan.Autorun_Generic.Malware.SF!dld!.D800E25F_241_1.vir, Trojan.Autorun_Trojan.Agent.EUMV_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.ByZ@aSgChKg.vir, Virus.Hijack_Gen.Trojan.ShellObject.ByZ@aSgChKg_1.vir, Virus.Hijack_Trojan.GenericKDZ.98113_164.vir, Virus.Hijack_Trojan.GenericKDZ.98113_260.vir, Virus.Hijack_Trojan.GenericKDZ.98113_349.vir, Virus.Hijack_Trojan.GenericKDZ.98113_385.vir, Virus.Hijack_Trojan.GenericKDZ.98113_90.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeee1f350aa61860b6e57ac2c089688f074e7147545530d623101f06843728d0"
    hash2       = "6c32fa84df69ef147f5a5a5dbf99590c120a1751c4e86486ecbadae6872cea08"
    hash3       = "397f4f047fca74c46e8223fad98874133869fc3ba876d3e87b23a6e7d3c5541a"
    hash4       = "9934b714afcd6f054b25e4942d0500bc78fe41634c6564d36476ceec069f25de"
    hash5       = "a986028cca57dbd858d8cb169eb1cea12859e452ca34de4db1d5085311d0e81a"
    hash6       = "877909f04c3a96ade758300fb345caa852c4f75f835f245fee70648dc5f2410a"
    hash7       = "60a402803ed45babc1901c6c5ecc3306bf8e57a7467e3cc91b154ad9103997ca"
    hash8       = "4fbc282dbf19d34c789d1c2ca0983fa23de6fa3daeb1245da8a055cc22f70aa8"
    hash9       = "264da6cc9e4d16effecccff861ea95b5a61fafa80f9ea4aaf74097db158c1c69"
    hash10      = "b9567a5dea8bda3c8b71bed884926dd7488145fe12fa644da157b3bd6f42ee3d"

  strings:
    $s1 = "Point: 0/1, f(x):0.9999964237213135, eval:<bound method CGeneticAlgorithm.f_eval of CGeneticAlgorithm{'classifier': CClassifierE" ascii
    $s2 = "nd2EndMalware{'classes': array([0, 1]), 'n_features': 1048576, 'preprocess': None, 'n_jobs': 1, 'model': MalConv(" fullword ascii
    $s3 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s4 = " 41.38803815841675}>/problem_': None, 'stagnation': 5, 'elapsed_time_': 62.08914589881897}>/[" fullword ascii
    $s5 = "ct at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': array([0.92182162, 0.37162541, 0.97213861, 0.09265248, 0.37131" ascii
    $s6 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.9999507665634155," ascii
    $s7 = "Point: 0/1, f(x):0.9999964237213135, eval:<bound method CGeneticAlgorithm.f_eval of CGeneticAlgorithm{'classifier': CClassifierE" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "62ec3dce1eba1b68f6a4511bb09f8c2c" and (all of them)
    ) or (all of them)
}