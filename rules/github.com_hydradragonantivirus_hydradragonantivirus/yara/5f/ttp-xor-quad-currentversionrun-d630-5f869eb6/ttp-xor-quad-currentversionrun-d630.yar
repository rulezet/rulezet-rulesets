rule TTP_XOR_QUAD_CurrentVersionRun_d630 {
  strings:
    $key_d630 = { 85 5f [2] a1 51 [2] 8a 7d [2] a4 5f [2] b0 44 [2] bf 5e [2] a1 43 [2] a3 42 [2] b8 44 [2] a4 43 [2] b8 6c }

  condition:
    any of them
}