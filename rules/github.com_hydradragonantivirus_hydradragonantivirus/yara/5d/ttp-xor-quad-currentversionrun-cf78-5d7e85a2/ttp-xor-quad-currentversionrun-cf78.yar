rule TTP_XOR_QUAD_CurrentVersionRun_cf78 {
  strings:
    $key_cf78 = { 9c 17 [2] b8 19 [2] 93 35 [2] bd 17 [2] a9 0c [2] a6 16 [2] b8 0b [2] ba 0a [2] a1 0c [2] bd 0b [2] a1 24 }

  condition:
    any of them
}