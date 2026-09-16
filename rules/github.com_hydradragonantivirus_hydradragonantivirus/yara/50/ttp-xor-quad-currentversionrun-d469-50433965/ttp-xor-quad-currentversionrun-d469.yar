rule TTP_XOR_QUAD_CurrentVersionRun_d469 {
  strings:
    $key_d469 = { 87 06 [2] a3 08 [2] 88 24 [2] a6 06 [2] b2 1d [2] bd 07 [2] a3 1a [2] a1 1b [2] ba 1d [2] a6 1a [2] ba 35 }

  condition:
    any of them
}