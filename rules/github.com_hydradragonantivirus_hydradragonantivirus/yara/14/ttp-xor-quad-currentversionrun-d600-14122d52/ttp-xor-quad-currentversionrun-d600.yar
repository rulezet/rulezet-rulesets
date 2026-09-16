rule TTP_XOR_QUAD_CurrentVersionRun_d600 {
  strings:
    $key_d600 = { 85 6f [2] a1 61 [2] 8a 4d [2] a4 6f [2] b0 74 [2] bf 6e [2] a1 73 [2] a3 72 [2] b8 74 [2] a4 73 [2] b8 5c }

  condition:
    any of them
}