rule TTP_XOR_QUAD_CurrentVersionRun_d479 {
  strings:
    $key_d479 = { 87 16 [2] a3 18 [2] 88 34 [2] a6 16 [2] b2 0d [2] bd 17 [2] a3 0a [2] a1 0b [2] ba 0d [2] a6 0a [2] ba 25 }

  condition:
    any of them
}