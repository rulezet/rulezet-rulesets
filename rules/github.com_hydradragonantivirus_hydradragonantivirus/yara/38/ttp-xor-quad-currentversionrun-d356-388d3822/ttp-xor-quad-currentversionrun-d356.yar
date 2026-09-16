rule TTP_XOR_QUAD_CurrentVersionRun_d356 {
  strings:
    $key_d356 = { 80 39 [2] a4 37 [2] 8f 1b [2] a1 39 [2] b5 22 [2] ba 38 [2] a4 25 [2] a6 24 [2] bd 22 [2] a1 25 [2] bd 0a }

  condition:
    any of them
}