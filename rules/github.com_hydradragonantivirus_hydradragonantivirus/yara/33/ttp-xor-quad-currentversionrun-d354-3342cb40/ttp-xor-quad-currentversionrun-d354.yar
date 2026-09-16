rule TTP_XOR_QUAD_CurrentVersionRun_d354 {
  strings:
    $key_d354 = { 80 3b [2] a4 35 [2] 8f 19 [2] a1 3b [2] b5 20 [2] ba 3a [2] a4 27 [2] a6 26 [2] bd 20 [2] a1 27 [2] bd 08 }

  condition:
    any of them
}