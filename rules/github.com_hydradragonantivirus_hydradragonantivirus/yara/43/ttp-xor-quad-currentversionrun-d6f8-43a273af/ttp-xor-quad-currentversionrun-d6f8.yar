rule TTP_XOR_QUAD_CurrentVersionRun_d6f8 {
  strings:
    $key_d6f8 = { 85 97 [2] a1 99 [2] 8a b5 [2] a4 97 [2] b0 8c [2] bf 96 [2] a1 8b [2] a3 8a [2] b8 8c [2] a4 8b [2] b8 a4 }

  condition:
    any of them
}