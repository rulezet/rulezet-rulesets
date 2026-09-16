rule TTP_XOR_QUAD_CurrentVersionRun_bb89 {
  strings:
    $key_bb89 = { e8 e6 [2] cc e8 [2] e7 c4 [2] c9 e6 [2] dd fd [2] d2 e7 [2] cc fa [2] ce fb [2] d5 fd [2] c9 fa [2] d5 d5 }

  condition:
    any of them
}