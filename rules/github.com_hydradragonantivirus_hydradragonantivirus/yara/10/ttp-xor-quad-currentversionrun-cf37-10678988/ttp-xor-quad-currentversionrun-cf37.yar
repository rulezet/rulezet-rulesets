rule TTP_XOR_QUAD_CurrentVersionRun_cf37 {
  strings:
    $key_cf37 = { 9c 58 [2] b8 56 [2] 93 7a [2] bd 58 [2] a9 43 [2] a6 59 [2] b8 44 [2] ba 45 [2] a1 43 [2] bd 44 [2] a1 6b }

  condition:
    any of them
}