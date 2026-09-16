rule TTP_XOR_QUAD_CurrentVersionRun_d67d {
  strings:
    $key_d67d = { 85 12 [2] a1 1c [2] 8a 30 [2] a4 12 [2] b0 09 [2] bf 13 [2] a1 0e [2] a3 0f [2] b8 09 [2] a4 0e [2] b8 21 }

  condition:
    any of them
}