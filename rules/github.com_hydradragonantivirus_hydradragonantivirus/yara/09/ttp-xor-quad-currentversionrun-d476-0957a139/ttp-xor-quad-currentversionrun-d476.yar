rule TTP_XOR_QUAD_CurrentVersionRun_d476 {
  strings:
    $key_d476 = { 87 19 [2] a3 17 [2] 88 3b [2] a6 19 [2] b2 02 [2] bd 18 [2] a3 05 [2] a1 04 [2] ba 02 [2] a6 05 [2] ba 2a }

  condition:
    any of them
}