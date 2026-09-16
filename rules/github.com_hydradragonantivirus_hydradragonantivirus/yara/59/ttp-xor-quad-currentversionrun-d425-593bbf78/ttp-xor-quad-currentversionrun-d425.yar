rule TTP_XOR_QUAD_CurrentVersionRun_d425 {
  strings:
    $key_d425 = { 87 4a [2] a3 44 [2] 88 68 [2] a6 4a [2] b2 51 [2] bd 4b [2] a3 56 [2] a1 57 [2] ba 51 [2] a6 56 [2] ba 79 }

  condition:
    any of them
}