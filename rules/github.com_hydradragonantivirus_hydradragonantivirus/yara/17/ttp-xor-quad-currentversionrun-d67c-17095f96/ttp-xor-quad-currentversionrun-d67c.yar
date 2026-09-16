rule TTP_XOR_QUAD_CurrentVersionRun_d67c {
  strings:
    $key_d67c = { 85 13 [2] a1 1d [2] 8a 31 [2] a4 13 [2] b0 08 [2] bf 12 [2] a1 0f [2] a3 0e [2] b8 08 [2] a4 0f [2] b8 20 }

  condition:
    any of them
}