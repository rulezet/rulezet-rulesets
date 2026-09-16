rule TTP_XOR_QUAD_CurrentVersionRun_ca59 {
  strings:
    $key_ca59 = { 99 36 [2] bd 38 [2] 96 14 [2] b8 36 [2] ac 2d [2] a3 37 [2] bd 2a [2] bf 2b [2] a4 2d [2] b8 2a [2] a4 05 }

  condition:
    any of them
}