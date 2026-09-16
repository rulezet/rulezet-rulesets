rule TTP_XOR_QUAD_CurrentVersionRun_3889 {
  strings:
    $key_3889 = { 6b e6 [2] 4f e8 [2] 64 c4 [2] 4a e6 [2] 5e fd [2] 51 e7 [2] 4f fa [2] 4d fb [2] 56 fd [2] 4a fa [2] 56 d5 }

  condition:
    any of them
}