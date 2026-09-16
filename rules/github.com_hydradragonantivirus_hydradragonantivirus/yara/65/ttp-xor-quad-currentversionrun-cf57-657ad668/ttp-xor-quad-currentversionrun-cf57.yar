rule TTP_XOR_QUAD_CurrentVersionRun_cf57 {
  strings:
    $key_cf57 = { 9c 38 [2] b8 36 [2] 93 1a [2] bd 38 [2] a9 23 [2] a6 39 [2] b8 24 [2] ba 25 [2] a1 23 [2] bd 24 [2] a1 0b }

  condition:
    any of them
}