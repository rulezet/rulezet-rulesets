rule TTP_XOR_QUAD_CurrentVersionRun_d650 {
  strings:
    $key_d650 = { 85 3f [2] a1 31 [2] 8a 1d [2] a4 3f [2] b0 24 [2] bf 3e [2] a1 23 [2] a3 22 [2] b8 24 [2] a4 23 [2] b8 0c }

  condition:
    any of them
}