rule TTP_XOR_QUAD_CurrentVersionRun_cf44 {
  strings:
    $key_cf44 = { 9c 2b [2] b8 25 [2] 93 09 [2] bd 2b [2] a9 30 [2] a6 2a [2] b8 37 [2] ba 36 [2] a1 30 [2] bd 37 [2] a1 18 }

  condition:
    any of them
}