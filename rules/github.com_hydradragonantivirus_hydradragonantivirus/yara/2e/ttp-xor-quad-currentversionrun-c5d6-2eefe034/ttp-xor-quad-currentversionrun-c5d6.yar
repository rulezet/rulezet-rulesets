rule TTP_XOR_QUAD_CurrentVersionRun_c5d6 {
  strings:
    $key_c5d6 = { 96 b9 [2] b2 b7 [2] 99 9b [2] b7 b9 [2] a3 a2 [2] ac b8 [2] b2 a5 [2] b0 a4 [2] ab a2 [2] b7 a5 [2] ab 8a }

  condition:
    any of them
}