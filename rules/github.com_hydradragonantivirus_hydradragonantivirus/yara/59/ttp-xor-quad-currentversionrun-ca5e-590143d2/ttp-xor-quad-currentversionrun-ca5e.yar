rule TTP_XOR_QUAD_CurrentVersionRun_ca5e {
  strings:
    $key_ca5e = { 99 31 [2] bd 3f [2] 96 13 [2] b8 31 [2] ac 2a [2] a3 30 [2] bd 2d [2] bf 2c [2] a4 2a [2] b8 2d [2] a4 02 }

  condition:
    any of them
}