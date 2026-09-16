rule TTP_XOR_QUAD_CurrentVersionRun_e8d7 {
  strings:
    $key_e8d7 = { bb b8 [2] 9f b6 [2] b4 9a [2] 9a b8 [2] 8e a3 [2] 81 b9 [2] 9f a4 [2] 9d a5 [2] 86 a3 [2] 9a a4 [2] 86 8b }

  condition:
    any of them
}