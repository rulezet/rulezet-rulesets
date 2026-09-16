rule TTP_XOR_QUAD_CurrentVersionRun_cf4d {
  strings:
    $key_cf4d = { 9c 22 [2] b8 2c [2] 93 00 [2] bd 22 [2] a9 39 [2] a6 23 [2] b8 3e [2] ba 3f [2] a1 39 [2] bd 3e [2] a1 11 }

  condition:
    any of them
}