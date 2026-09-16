rule TTP_XOR_QUAD_CurrentVersionRun_d679 {
  strings:
    $key_d679 = { 85 16 [2] a1 18 [2] 8a 34 [2] a4 16 [2] b0 0d [2] bf 17 [2] a1 0a [2] a3 0b [2] b8 0d [2] a4 0a [2] b8 25 }

  condition:
    any of them
}