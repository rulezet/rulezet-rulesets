rule TTP_XOR_QUAD_CurrentVersionRun_ac88 {
  strings:
    $key_ac88 = { ff e7 [2] db e9 [2] f0 c5 [2] de e7 [2] ca fc [2] c5 e6 [2] db fb [2] d9 fa [2] c2 fc [2] de fb [2] c2 d4 }

  condition:
    any of them
}