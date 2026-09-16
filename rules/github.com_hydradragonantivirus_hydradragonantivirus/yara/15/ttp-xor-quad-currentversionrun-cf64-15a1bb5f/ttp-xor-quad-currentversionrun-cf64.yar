rule TTP_XOR_QUAD_CurrentVersionRun_cf64 {
  strings:
    $key_cf64 = { 9c 0b [2] b8 05 [2] 93 29 [2] bd 0b [2] a9 10 [2] a6 0a [2] b8 17 [2] ba 16 [2] a1 10 [2] bd 17 [2] a1 38 }

  condition:
    any of them
}