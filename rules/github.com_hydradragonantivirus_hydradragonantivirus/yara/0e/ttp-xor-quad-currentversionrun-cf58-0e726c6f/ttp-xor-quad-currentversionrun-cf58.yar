rule TTP_XOR_QUAD_CurrentVersionRun_cf58 {
  strings:
    $key_cf58 = { 9c 37 [2] b8 39 [2] 93 15 [2] bd 37 [2] a9 2c [2] a6 36 [2] b8 2b [2] ba 2a [2] a1 2c [2] bd 2b [2] a1 04 }

  condition:
    any of them
}