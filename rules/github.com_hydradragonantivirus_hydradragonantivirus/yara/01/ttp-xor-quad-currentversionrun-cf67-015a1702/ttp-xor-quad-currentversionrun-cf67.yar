rule TTP_XOR_QUAD_CurrentVersionRun_cf67 {
  strings:
    $key_cf67 = { 9c 08 [2] b8 06 [2] 93 2a [2] bd 08 [2] a9 13 [2] a6 09 [2] b8 14 [2] ba 15 [2] a1 13 [2] bd 14 [2] a1 3b }

  condition:
    any of them
}