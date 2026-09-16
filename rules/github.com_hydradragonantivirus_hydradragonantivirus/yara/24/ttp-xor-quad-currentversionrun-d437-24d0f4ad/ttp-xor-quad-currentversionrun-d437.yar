rule TTP_XOR_QUAD_CurrentVersionRun_d437 {
  strings:
    $key_d437 = { 87 58 [2] a3 56 [2] 88 7a [2] a6 58 [2] b2 43 [2] bd 59 [2] a3 44 [2] a1 45 [2] ba 43 [2] a6 44 [2] ba 6b }

  condition:
    any of them
}