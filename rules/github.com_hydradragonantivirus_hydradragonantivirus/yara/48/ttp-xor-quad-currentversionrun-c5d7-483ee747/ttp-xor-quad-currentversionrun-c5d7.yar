rule TTP_XOR_QUAD_CurrentVersionRun_c5d7 {
  strings:
    $key_c5d7 = { 96 b8 [2] b2 b6 [2] 99 9a [2] b7 b8 [2] a3 a3 [2] ac b9 [2] b2 a4 [2] b0 a5 [2] ab a3 [2] b7 a4 [2] ab 8b }

  condition:
    any of them
}