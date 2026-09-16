rule TTP_XOR_QUAD_CurrentVersionRun_cf4c {
  strings:
    $key_cf4c = { 9c 23 [2] b8 2d [2] 93 01 [2] bd 23 [2] a9 38 [2] a6 22 [2] b8 3f [2] ba 3e [2] a1 38 [2] bd 3f [2] a1 10 }

  condition:
    any of them
}