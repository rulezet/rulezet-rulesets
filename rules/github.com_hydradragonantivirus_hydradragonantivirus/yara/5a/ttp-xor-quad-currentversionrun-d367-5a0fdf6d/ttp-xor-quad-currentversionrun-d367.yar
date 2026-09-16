rule TTP_XOR_QUAD_CurrentVersionRun_d367 {
  strings:
    $key_d367 = { 80 08 [2] a4 06 [2] 8f 2a [2] a1 08 [2] b5 13 [2] ba 09 [2] a4 14 [2] a6 15 [2] bd 13 [2] a1 14 [2] bd 3b }

  condition:
    any of them
}