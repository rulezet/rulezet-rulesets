rule TTP_XOR_QUAD_CurrentVersionRun_d6f9 {
  strings:
    $key_d6f9 = { 85 96 [2] a1 98 [2] 8a b4 [2] a4 96 [2] b0 8d [2] bf 97 [2] a1 8a [2] a3 8b [2] b8 8d [2] a4 8a [2] b8 a5 }

  condition:
    any of them
}