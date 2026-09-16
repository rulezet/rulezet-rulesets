rule TTP_XOR_QUAD_CurrentVersionRun_d454 {
  strings:
    $key_d454 = { 87 3b [2] a3 35 [2] 88 19 [2] a6 3b [2] b2 20 [2] bd 3a [2] a3 27 [2] a1 26 [2] ba 20 [2] a6 27 [2] ba 08 }

  condition:
    any of them
}