rule TTP_XOR_QUAD_CurrentVersionRun_aa9c {
  strings:
    $key_aa9c = { f9 f3 [2] dd fd [2] f6 d1 [2] d8 f3 [2] cc e8 [2] c3 f2 [2] dd ef [2] df ee [2] c4 e8 [2] d8 ef [2] c4 c0 }

  condition:
    any of them
}