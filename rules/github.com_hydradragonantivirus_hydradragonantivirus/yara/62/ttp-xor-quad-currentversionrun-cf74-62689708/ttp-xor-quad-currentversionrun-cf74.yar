rule TTP_XOR_QUAD_CurrentVersionRun_cf74 {
  strings:
    $key_cf74 = { 9c 1b [2] b8 15 [2] 93 39 [2] bd 1b [2] a9 00 [2] a6 1a [2] b8 07 [2] ba 06 [2] a1 00 [2] bd 07 [2] a1 28 }

  condition:
    any of them
}