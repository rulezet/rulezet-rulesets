rule TTP_XOR_QUAD_CurrentVersionRun_c6f3 {
  strings:
    $key_c6f3 = { 95 9c [2] b1 92 [2] 9a be [2] b4 9c [2] a0 87 [2] af 9d [2] b1 80 [2] b3 81 [2] a8 87 [2] b4 80 [2] a8 af }

  condition:
    any of them
}