import "pe"
rule _Virus_Hijack_Backdoor_Hangup_B_296_1_Virus_Hijack_Backdoor_Hang_208 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Backdoor.Hangup.B_296_1.vir, Virus.Hijack_Backdoor.Hangup.B_308_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9c380bb96b2fa33725f825d0ad541831482da51077b05446bf0b9af4f37c99b"
    hash2       = "5e0dfc77e453787f366f57bc9c7d698ce6c40652454d2f052d4cf4890452ab76"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3 = "esult_': array([9.51985840e-02, 1.25080667e-01, 8.03580464e-01, 1.04336451e-02," fullword ascii
    $s4 = "': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_r" ascii
    $s5 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.00092345458688214" ascii
    $s6 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.9987990856170654," ascii
    $s7 = "  (dense_2): Linear(in_featu" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "cdf5bbb8693f29ef22aef04d2a161dd7" and (all of them)
    ) or (all of them)
}