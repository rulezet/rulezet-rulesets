rule TTP_XOR_QUAD_CurrentVersionRun_d309 {
  strings:
    $key_d309 = { 80 66 [2] a4 68 [2] 8f 44 [2] a1 66 [2] b5 7d [2] ba 67 [2] a4 7a [2] a6 7b [2] bd 7d [2] a1 7a [2] bd 55 }

  condition:
    any of them
}