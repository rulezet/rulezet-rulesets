rule TTP_XOR_QUAD_CurrentVersionRun_b689 {
  strings:
    $key_b689 = { e5 e6 [2] c1 e8 [2] ea c4 [2] c4 e6 [2] d0 fd [2] df e7 [2] c1 fa [2] c3 fb [2] d8 fd [2] c4 fa [2] d8 d5 }

  condition:
    any of them
}