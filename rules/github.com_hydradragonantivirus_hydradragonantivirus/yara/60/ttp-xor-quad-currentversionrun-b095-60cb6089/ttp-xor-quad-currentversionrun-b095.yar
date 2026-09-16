rule TTP_XOR_QUAD_CurrentVersionRun_b095 {
  strings:
    $key_b095 = { e3 fa [2] c7 f4 [2] ec d8 [2] c2 fa [2] d6 e1 [2] d9 fb [2] c7 e6 [2] c5 e7 [2] de e1 [2] c2 e6 [2] de c9 }

  condition:
    any of them
}