rule Virus_Hijack_Backdoor_Hangup_B_299_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_299_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8236af355103f2dfb7214ec984d1785fb88f63045a61e14ab7f204dfbdc88fc7"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "rapper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimiza" ascii
    $s3 = "324133, 324133, 324133, 324133, 324133, 324133, 324133, 324133, 324133, 324133, 324133, 324133, 324133, 324133, 324133, 324133, " ascii
    $s4 = "  (dense_2): Linear(in_features=128, out_features=1, bias=T" fullword ascii
    $s5 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.7238167524337769," ascii
    $s6 = "tion_result_': array([0.43890482, 0.13163895, 0.23726332, 0.07941007, 0.39697099," fullword ascii
    $s7 = ", 0.003860080149024725, 0.003860080149024725, 0.003860080149024725, 0.003860080149024725, 0.003860080149024725, 0.00386008014902" ascii
    $s8 = "r_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}