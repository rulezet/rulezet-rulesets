rule TTP_XOR_QUAD_CurrentVersionRun_d44d {
  strings:
    $key_d44d = { 87 22 [2] a3 2c [2] 88 00 [2] a6 22 [2] b2 39 [2] bd 23 [2] a3 3e [2] a1 3f [2] ba 39 [2] a6 3e [2] ba 11 }

  condition:
    any of them
}