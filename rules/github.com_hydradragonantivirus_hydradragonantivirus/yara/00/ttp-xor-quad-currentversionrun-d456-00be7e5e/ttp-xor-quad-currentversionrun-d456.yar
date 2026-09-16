rule TTP_XOR_QUAD_CurrentVersionRun_d456 {
  strings:
    $key_d456 = { 87 39 [2] a3 37 [2] 88 1b [2] a6 39 [2] b2 22 [2] bd 38 [2] a3 25 [2] a1 24 [2] ba 22 [2] a6 25 [2] ba 0a }

  condition:
    any of them
}