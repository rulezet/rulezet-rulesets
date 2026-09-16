rule TTP_XOR_QUAD_CurrentVersionRun_cf69 {
  strings:
    $key_cf69 = { 9c 06 [2] b8 08 [2] 93 24 [2] bd 06 [2] a9 1d [2] a6 07 [2] b8 1a [2] ba 1b [2] a1 1d [2] bd 1a [2] a1 35 }

  condition:
    any of them
}