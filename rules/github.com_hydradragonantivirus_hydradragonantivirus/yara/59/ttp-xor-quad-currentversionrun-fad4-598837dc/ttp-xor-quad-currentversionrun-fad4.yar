rule TTP_XOR_QUAD_CurrentVersionRun_fad4 {
  strings:
    $key_fad4 = { a9 bb [2] 8d b5 [2] a6 99 [2] 88 bb [2] 9c a0 [2] 93 ba [2] 8d a7 [2] 8f a6 [2] 94 a0 [2] 88 a7 [2] 94 88 }

  condition:
    any of them
}