rule TTP_XOR_QUAD_CurrentVersionRun_d464 {
  strings:
    $key_d464 = { 87 0b [2] a3 05 [2] 88 29 [2] a6 0b [2] b2 10 [2] bd 0a [2] a3 17 [2] a1 16 [2] ba 10 [2] a6 17 [2] ba 38 }

  condition:
    any of them
}