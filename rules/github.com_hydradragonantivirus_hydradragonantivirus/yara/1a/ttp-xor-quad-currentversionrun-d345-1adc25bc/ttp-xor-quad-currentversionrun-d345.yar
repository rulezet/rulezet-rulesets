rule TTP_XOR_QUAD_CurrentVersionRun_d345 {
  strings:
    $key_d345 = { 80 2a [2] a4 24 [2] 8f 08 [2] a1 2a [2] b5 31 [2] ba 2b [2] a4 36 [2] a6 37 [2] bd 31 [2] a1 36 [2] bd 19 }

  condition:
    any of them
}