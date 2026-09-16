rule TTP_XOR_QUAD_CurrentVersionRun_d463 {
  strings:
    $key_d463 = { 87 0c [2] a3 02 [2] 88 2e [2] a6 0c [2] b2 17 [2] bd 0d [2] a3 10 [2] a1 11 [2] ba 17 [2] a6 10 [2] ba 3f }

  condition:
    any of them
}