rule TTP_XOR_QUAD_CurrentVersionRun_cf2c {
  strings:
    $key_cf2c = { 9c 43 [2] b8 4d [2] 93 61 [2] bd 43 [2] a9 58 [2] a6 42 [2] b8 5f [2] ba 5e [2] a1 58 [2] bd 5f [2] a1 70 }

  condition:
    any of them
}