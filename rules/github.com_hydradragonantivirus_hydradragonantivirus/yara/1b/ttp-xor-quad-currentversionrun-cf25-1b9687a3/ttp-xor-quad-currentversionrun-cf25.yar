rule TTP_XOR_QUAD_CurrentVersionRun_cf25 {
  strings:
    $key_cf25 = { 9c 4a [2] b8 44 [2] 93 68 [2] bd 4a [2] a9 51 [2] a6 4b [2] b8 56 [2] ba 57 [2] a1 51 [2] bd 56 [2] a1 79 }

  condition:
    any of them
}