rule TTP_XOR_QUAD_CurrentVersionRun_ca75 {
  strings:
    $key_ca75 = { 99 1a [2] bd 14 [2] 96 38 [2] b8 1a [2] ac 01 [2] a3 1b [2] bd 06 [2] bf 07 [2] a4 01 [2] b8 06 [2] a4 29 }

  condition:
    any of them
}