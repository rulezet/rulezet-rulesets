rule TTP_XOR_QUAD_CurrentVersionRun_2494 {
  strings:
    $key_2494 = { 77 fb [2] 53 f5 [2] 78 d9 [2] 56 fb [2] 42 e0 [2] 4d fa [2] 53 e7 [2] 51 e6 [2] 4a e0 [2] 56 e7 [2] 4a c8 }

  condition:
    any of them
}