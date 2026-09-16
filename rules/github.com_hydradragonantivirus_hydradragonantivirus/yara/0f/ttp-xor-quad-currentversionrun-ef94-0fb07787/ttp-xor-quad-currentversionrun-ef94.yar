rule TTP_XOR_QUAD_CurrentVersionRun_ef94 {
  strings:
    $key_ef94 = { bc fb [2] 98 f5 [2] b3 d9 [2] 9d fb [2] 89 e0 [2] 86 fa [2] 98 e7 [2] 9a e6 [2] 81 e0 [2] 9d e7 [2] 81 c8 }

  condition:
    any of them
}