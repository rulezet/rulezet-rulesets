rule TTP_XOR_QUAD_CurrentVersionRun_c5f4 {
  strings:
    $key_c5f4 = { 96 9b [2] b2 95 [2] 99 b9 [2] b7 9b [2] a3 80 [2] ac 9a [2] b2 87 [2] b0 86 [2] ab 80 [2] b7 87 [2] ab a8 }

  condition:
    any of them
}