rule TTP_XOR_QUAD_CurrentVersionRun_bfc7 {
  strings:
    $key_bfc7 = { ec a8 [2] c8 a6 [2] e3 8a [2] cd a8 [2] d9 b3 [2] d6 a9 [2] c8 b4 [2] ca b5 [2] d1 b3 [2] cd b4 [2] d1 9b }

  condition:
    any of them
}