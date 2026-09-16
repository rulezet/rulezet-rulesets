rule TTP_XOR_QUAD_CurrentVersionRun_d359 {
  strings:
    $key_d359 = { 80 36 [2] a4 38 [2] 8f 14 [2] a1 36 [2] b5 2d [2] ba 37 [2] a4 2a [2] a6 2b [2] bd 2d [2] a1 2a [2] bd 05 }

  condition:
    any of them
}