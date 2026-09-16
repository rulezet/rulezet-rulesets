rule TTP_XOR_QUAD_CurrentVersionRun_cf42 {
  strings:
    $key_cf42 = { 9c 2d [2] b8 23 [2] 93 0f [2] bd 2d [2] a9 36 [2] a6 2c [2] b8 31 [2] ba 30 [2] a1 36 [2] bd 31 [2] a1 1e }

  condition:
    any of them
}