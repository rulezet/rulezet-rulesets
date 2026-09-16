rule TTP_XOR_QUAD_CurrentVersionRun_d455 {
  strings:
    $key_d455 = { 87 3a [2] a3 34 [2] 88 18 [2] a6 3a [2] b2 21 [2] bd 3b [2] a3 26 [2] a1 27 [2] ba 21 [2] a6 26 [2] ba 09 }

  condition:
    any of them
}