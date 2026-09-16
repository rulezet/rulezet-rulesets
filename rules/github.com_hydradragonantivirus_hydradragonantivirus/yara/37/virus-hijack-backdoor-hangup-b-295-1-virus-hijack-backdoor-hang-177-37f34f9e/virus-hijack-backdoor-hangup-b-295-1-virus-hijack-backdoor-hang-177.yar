import "pe"
rule _Virus_Hijack_Backdoor_Hangup_B_295_1_Virus_Hijack_Backdoor_Hang_177 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Backdoor.Hangup.B_295_1.vir, Virus.Hijack_Backdoor.Hangup.B_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9a79b9657903c76da171921779864da57f038c35b1863504433171243bfa280"
    hash2       = "49a9829eb96637f964086657ac086d03db32bf4307662b57dfdd8a50854480de"

  strings:
    $s1  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s4  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s5  = "ptimizer': None, 'optimizer_scheduler': None, 'epochs': 100, 'plus_version': False, 'train_transform': Lambda()}, 'x" fullword ascii
    $s6  = "hape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binarp" fullword ascii
    $s7  = "alware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug'(r" fullword ascii
    $s8  = "ult_': array([0.75087719, 0.0578802 , 0.27883433, 0.06245839, 0.46756235," fullword ascii
    $s9  = " 0.06495549, 0.52186315, 0.96296801]), 'evolved_problem_': None, 'stagnation': 5, 'elapsed_time_': 38.5603511333" fullword ascii
    $s10 = " <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_res" ascii
    $s11 = " 0.043230801820755005, 0.043230801820755005, 0.043230801820755005, 0.043230801820755005, 0.043230801820755005, 0.043230801820755" ascii
    $s12 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.5788450241088867," ascii
    $s13 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.43616196513175964" ascii
    $s14 = "CGeneticAlgorithm{'classifier': CClassifierEnd2EndMalware{'classes': array([0, 1]), 'n_" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "cdf5bbb8693f29ef22aef04d2a161dd7" and (8 of them)
    ) or (all of them)
}