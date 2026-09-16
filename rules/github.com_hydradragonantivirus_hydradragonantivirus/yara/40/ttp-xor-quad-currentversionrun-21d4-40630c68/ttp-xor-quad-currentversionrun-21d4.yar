rule TTP_XOR_QUAD_CurrentVersionRun_21d4 {
  strings:
    $key_21d4 = { 72 bb [2] 56 b5 [2] 7d 99 [2] 53 bb [2] 47 a0 [2] 48 ba [2] 56 a7 [2] 54 a6 [2] 4f a0 [2] 53 a7 [2] 4f 88 }

  condition:
    any of them
}