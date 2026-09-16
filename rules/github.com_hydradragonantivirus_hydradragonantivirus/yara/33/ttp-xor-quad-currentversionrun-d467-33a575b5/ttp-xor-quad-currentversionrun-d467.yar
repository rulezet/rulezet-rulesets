rule TTP_XOR_QUAD_CurrentVersionRun_d467 {
  strings:
    $key_d467 = { 87 08 [2] a3 06 [2] 88 2a [2] a6 08 [2] b2 13 [2] bd 09 [2] a3 14 [2] a1 15 [2] ba 13 [2] a6 14 [2] ba 3b }

  condition:
    any of them
}