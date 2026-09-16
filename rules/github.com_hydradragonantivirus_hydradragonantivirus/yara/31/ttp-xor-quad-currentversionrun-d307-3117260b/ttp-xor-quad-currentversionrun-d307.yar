rule TTP_XOR_QUAD_CurrentVersionRun_d307 {
  strings:
    $key_d307 = { 80 68 [2] a4 66 [2] 8f 4a [2] a1 68 [2] b5 73 [2] ba 69 [2] a4 74 [2] a6 75 [2] bd 73 [2] a1 74 [2] bd 5b }

  condition:
    any of them
}