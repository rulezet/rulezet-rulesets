rule TTP_XOR_QUAD_CurrentVersionRun_d474 {
  strings:
    $key_d474 = { 87 1b [2] a3 15 [2] 88 39 [2] a6 1b [2] b2 00 [2] bd 1a [2] a3 07 [2] a1 06 [2] ba 00 [2] a6 07 [2] ba 28 }

  condition:
    any of them
}