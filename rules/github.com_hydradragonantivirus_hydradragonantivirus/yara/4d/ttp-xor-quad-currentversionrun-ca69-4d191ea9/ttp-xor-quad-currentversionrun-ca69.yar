rule TTP_XOR_QUAD_CurrentVersionRun_ca69 {
  strings:
    $key_ca69 = { 99 06 [2] bd 08 [2] 96 24 [2] b8 06 [2] ac 1d [2] a3 07 [2] bd 1a [2] bf 1b [2] a4 1d [2] b8 1a [2] a4 35 }

  condition:
    any of them
}