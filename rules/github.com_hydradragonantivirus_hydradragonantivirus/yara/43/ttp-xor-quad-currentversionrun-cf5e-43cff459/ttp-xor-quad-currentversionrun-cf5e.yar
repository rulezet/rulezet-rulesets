rule TTP_XOR_QUAD_CurrentVersionRun_cf5e {
  strings:
    $key_cf5e = { 9c 31 [2] b8 3f [2] 93 13 [2] bd 31 [2] a9 2a [2] a6 30 [2] b8 2d [2] ba 2c [2] a1 2a [2] bd 2d [2] a1 02 }

  condition:
    any of them
}