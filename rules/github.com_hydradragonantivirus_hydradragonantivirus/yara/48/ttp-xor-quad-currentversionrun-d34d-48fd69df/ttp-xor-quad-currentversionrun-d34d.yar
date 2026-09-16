rule TTP_XOR_QUAD_CurrentVersionRun_d34d {
  strings:
    $key_d34d = { 80 22 [2] a4 2c [2] 8f 00 [2] a1 22 [2] b5 39 [2] ba 23 [2] a4 3e [2] a6 3f [2] bd 39 [2] a1 3e [2] bd 11 }

  condition:
    any of them
}