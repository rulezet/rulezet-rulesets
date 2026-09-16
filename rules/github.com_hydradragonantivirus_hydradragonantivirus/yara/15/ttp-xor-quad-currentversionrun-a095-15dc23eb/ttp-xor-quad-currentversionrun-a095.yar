rule TTP_XOR_QUAD_CurrentVersionRun_a095 {
  strings:
    $key_a095 = { f3 fa [2] d7 f4 [2] fc d8 [2] d2 fa [2] c6 e1 [2] c9 fb [2] d7 e6 [2] d5 e7 [2] ce e1 [2] d2 e6 [2] ce c9 }

  condition:
    any of them
}