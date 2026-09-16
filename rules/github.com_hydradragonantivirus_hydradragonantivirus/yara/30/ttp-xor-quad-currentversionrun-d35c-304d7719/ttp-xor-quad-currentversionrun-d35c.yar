rule TTP_XOR_QUAD_CurrentVersionRun_d35c {
  strings:
    $key_d35c = { 80 33 [2] a4 3d [2] 8f 11 [2] a1 33 [2] b5 28 [2] ba 32 [2] a4 2f [2] a6 2e [2] bd 28 [2] a1 2f [2] bd 00 }

  condition:
    any of them
}