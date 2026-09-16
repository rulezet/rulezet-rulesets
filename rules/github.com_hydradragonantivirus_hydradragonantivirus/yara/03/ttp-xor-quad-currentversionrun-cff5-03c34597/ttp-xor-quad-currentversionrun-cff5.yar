rule TTP_XOR_QUAD_CurrentVersionRun_cff5 {
  strings:
    $key_cff5 = { 9c 9a [2] b8 94 [2] 93 b8 [2] bd 9a [2] a9 81 [2] a6 9b [2] b8 86 [2] ba 87 [2] a1 81 [2] bd 86 [2] a1 a9 }

  condition:
    any of them
}