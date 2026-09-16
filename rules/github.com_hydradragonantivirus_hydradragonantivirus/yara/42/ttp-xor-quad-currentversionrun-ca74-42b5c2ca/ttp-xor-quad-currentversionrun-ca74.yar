rule TTP_XOR_QUAD_CurrentVersionRun_ca74 {
  strings:
    $key_ca74 = { 99 1b [2] bd 15 [2] 96 39 [2] b8 1b [2] ac 00 [2] a3 1a [2] bd 07 [2] bf 06 [2] a4 00 [2] b8 07 [2] a4 28 }

  condition:
    any of them
}