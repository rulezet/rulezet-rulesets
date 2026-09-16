rule TTP_XOR_QUAD_CurrentVersionRun_d325 {
  strings:
    $key_d325 = { 80 4a [2] a4 44 [2] 8f 68 [2] a1 4a [2] b5 51 [2] ba 4b [2] a4 56 [2] a6 57 [2] bd 51 [2] a1 56 [2] bd 79 }

  condition:
    any of them
}