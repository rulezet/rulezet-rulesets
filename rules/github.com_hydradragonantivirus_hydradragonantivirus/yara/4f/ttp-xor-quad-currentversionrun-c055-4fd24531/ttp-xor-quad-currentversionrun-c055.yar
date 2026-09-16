rule TTP_XOR_QUAD_CurrentVersionRun_c055 {
  strings:
    $key_c055 = { 93 3a [2] b7 34 [2] 9c 18 [2] b2 3a [2] a6 21 [2] a9 3b [2] b7 26 [2] b5 27 [2] ae 21 [2] b2 26 [2] ae 09 }

  condition:
    any of them
}