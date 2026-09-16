rule TTP_XOR_QUAD_CurrentVersionRun_fac7 {
  strings:
    $key_fac7 = { a9 a8 [2] 8d a6 [2] a6 8a [2] 88 a8 [2] 9c b3 [2] 93 a9 [2] 8d b4 [2] 8f b5 [2] 94 b3 [2] 88 b4 [2] 94 9b }

  condition:
    any of them
}