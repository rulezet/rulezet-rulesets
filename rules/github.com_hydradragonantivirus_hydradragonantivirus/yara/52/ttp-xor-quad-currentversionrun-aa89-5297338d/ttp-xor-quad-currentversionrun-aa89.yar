rule TTP_XOR_QUAD_CurrentVersionRun_aa89 {
  strings:
    $key_aa89 = { f9 e6 [2] dd e8 [2] f6 c4 [2] d8 e6 [2] cc fd [2] c3 e7 [2] dd fa [2] df fb [2] c4 fd [2] d8 fa [2] c4 d5 }

  condition:
    any of them
}