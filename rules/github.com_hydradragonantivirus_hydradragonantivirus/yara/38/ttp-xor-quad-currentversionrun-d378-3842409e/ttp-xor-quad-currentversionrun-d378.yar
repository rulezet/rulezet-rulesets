rule TTP_XOR_QUAD_CurrentVersionRun_d378 {
  strings:
    $key_d378 = { 80 17 [2] a4 19 [2] 8f 35 [2] a1 17 [2] b5 0c [2] ba 16 [2] a4 0b [2] a6 0a [2] bd 0c [2] a1 0b [2] bd 24 }

  condition:
    any of them
}