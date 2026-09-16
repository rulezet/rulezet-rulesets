rule TTP_XOR_QUAD_CurrentVersionRun_b788 {
  strings:
    $key_b788 = { e4 e7 [2] c0 e9 [2] eb c5 [2] c5 e7 [2] d1 fc [2] de e6 [2] c0 fb [2] c2 fa [2] d9 fc [2] c5 fb [2] d9 d4 }

  condition:
    any of them
}