rule TTP_XOR_QUAD_CurrentVersionRun_d374 {
  strings:
    $key_d374 = { 80 1b [2] a4 15 [2] 8f 39 [2] a1 1b [2] b5 00 [2] ba 1a [2] a4 07 [2] a6 06 [2] bd 00 [2] a1 07 [2] bd 28 }

  condition:
    any of them
}