rule TTP_XOR_QUAD_CurrentVersionRun_ca68 {
  strings:
    $key_ca68 = { 99 07 [2] bd 09 [2] 96 25 [2] b8 07 [2] ac 1c [2] a3 06 [2] bd 1b [2] bf 1a [2] a4 1c [2] b8 1b [2] a4 34 }

  condition:
    any of them
}