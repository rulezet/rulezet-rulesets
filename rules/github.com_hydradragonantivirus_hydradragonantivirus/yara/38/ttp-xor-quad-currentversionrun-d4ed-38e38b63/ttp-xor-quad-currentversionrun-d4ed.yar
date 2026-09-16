rule TTP_XOR_QUAD_CurrentVersionRun_d4ed {
  strings:
    $key_d4ed = { 87 82 [2] a3 8c [2] 88 a0 [2] a6 82 [2] b2 99 [2] bd 83 [2] a3 9e [2] a1 9f [2] ba 99 [2] a6 9e [2] ba b1 }

  condition:
    any of them
}