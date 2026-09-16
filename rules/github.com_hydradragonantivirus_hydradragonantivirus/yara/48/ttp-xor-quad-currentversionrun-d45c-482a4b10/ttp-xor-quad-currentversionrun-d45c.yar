rule TTP_XOR_QUAD_CurrentVersionRun_d45c {
  strings:
    $key_d45c = { 87 33 [2] a3 3d [2] 88 11 [2] a6 33 [2] b2 28 [2] bd 32 [2] a3 2f [2] a1 2e [2] ba 28 [2] a6 2f [2] ba 00 }

  condition:
    any of them
}