rule TTP_XOR_QUAD_CurrentVersionRun_d666 {
  strings:
    $key_d666 = { 85 09 [2] a1 07 [2] 8a 2b [2] a4 09 [2] b0 12 [2] bf 08 [2] a1 15 [2] a3 14 [2] b8 12 [2] a4 15 [2] b8 3a }

  condition:
    any of them
}