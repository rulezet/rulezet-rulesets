rule TTP_XOR_QUAD_CurrentVersionRun_f559 {
  strings:
    $key_f559 = { a6 36 [2] 82 38 [2] a9 14 [2] 87 36 [2] 93 2d [2] 9c 37 [2] 82 2a [2] 80 2b [2] 9b 2d [2] 87 2a [2] 9b 05 }

  condition:
    any of them
}