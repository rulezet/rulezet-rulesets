rule TTP_XOR_QUAD_CurrentVersionRun_cf65 {
  strings:
    $key_cf65 = { 9c 0a [2] b8 04 [2] 93 28 [2] bd 0a [2] a9 11 [2] a6 0b [2] b8 16 [2] ba 17 [2] a1 11 [2] bd 16 [2] a1 39 }

  condition:
    any of them
}