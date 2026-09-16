rule TTP_XOR_QUAD_CurrentVersionRun_a994 {
  strings:
    $key_a994 = { fa fb [2] de f5 [2] f5 d9 [2] db fb [2] cf e0 [2] c0 fa [2] de e7 [2] dc e6 [2] c7 e0 [2] db e7 [2] c7 c8 }

  condition:
    any of them
}