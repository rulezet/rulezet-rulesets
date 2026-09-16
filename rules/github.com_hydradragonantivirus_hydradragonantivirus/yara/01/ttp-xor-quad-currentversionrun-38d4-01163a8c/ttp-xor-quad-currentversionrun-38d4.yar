rule TTP_XOR_QUAD_CurrentVersionRun_38d4 {
  strings:
    $key_38d4 = { 6b bb [2] 4f b5 [2] 64 99 [2] 4a bb [2] 5e a0 [2] 51 ba [2] 4f a7 [2] 4d a6 [2] 56 a0 [2] 4a a7 [2] 56 88 }

  condition:
    any of them
}