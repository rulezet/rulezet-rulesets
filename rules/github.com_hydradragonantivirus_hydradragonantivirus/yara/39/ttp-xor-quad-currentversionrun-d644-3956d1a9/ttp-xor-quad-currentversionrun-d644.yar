rule TTP_XOR_QUAD_CurrentVersionRun_d644 {
  strings:
    $key_d644 = { 85 2b [2] a1 25 [2] 8a 09 [2] a4 2b [2] b0 30 [2] bf 2a [2] a1 37 [2] a3 36 [2] b8 30 [2] a4 37 [2] b8 18 }

  condition:
    any of them
}