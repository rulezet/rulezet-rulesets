rule TTP_XOR_QUAD_CurrentVersionRun_c5da {
  strings:
    $key_c5da = { 96 b5 [2] b2 bb [2] 99 97 [2] b7 b5 [2] a3 ae [2] ac b4 [2] b2 a9 [2] b0 a8 [2] ab ae [2] b7 a9 [2] ab 86 }

  condition:
    any of them
}