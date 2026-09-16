rule TTP_XOR_QUAD_CurrentVersionRun_d668 {
  strings:
    $key_d668 = { 85 07 [2] a1 09 [2] 8a 25 [2] a4 07 [2] b0 1c [2] bf 06 [2] a1 1b [2] a3 1a [2] b8 1c [2] a4 1b [2] b8 34 }

  condition:
    any of them
}