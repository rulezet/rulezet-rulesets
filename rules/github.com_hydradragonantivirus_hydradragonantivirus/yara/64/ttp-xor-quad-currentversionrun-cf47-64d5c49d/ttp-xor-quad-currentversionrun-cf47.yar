rule TTP_XOR_QUAD_CurrentVersionRun_cf47 {
  strings:
    $key_cf47 = { 9c 28 [2] b8 26 [2] 93 0a [2] bd 28 [2] a9 33 [2] a6 29 [2] b8 34 [2] ba 35 [2] a1 33 [2] bd 34 [2] a1 1b }

  condition:
    any of them
}