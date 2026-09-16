rule TTP_XOR_QUAD_CurrentVersionRun_cf55 {
  strings:
    $key_cf55 = { 9c 3a [2] b8 34 [2] 93 18 [2] bd 3a [2] a9 21 [2] a6 3b [2] b8 26 [2] ba 27 [2] a1 21 [2] bd 26 [2] a1 09 }

  condition:
    any of them
}