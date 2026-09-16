rule TTP_XOR_QUAD_CurrentVersionRun_d67b {
  strings:
    $key_d67b = { 85 14 [2] a1 1a [2] 8a 36 [2] a4 14 [2] b0 0f [2] bf 15 [2] a1 08 [2] a3 09 [2] b8 0f [2] a4 08 [2] b8 27 }

  condition:
    any of them
}