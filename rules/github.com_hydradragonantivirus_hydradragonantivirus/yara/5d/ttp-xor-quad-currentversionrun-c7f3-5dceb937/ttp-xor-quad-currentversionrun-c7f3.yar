rule TTP_XOR_QUAD_CurrentVersionRun_c7f3 {
  strings:
    $key_c7f3 = { 94 9c [2] b0 92 [2] 9b be [2] b5 9c [2] a1 87 [2] ae 9d [2] b0 80 [2] b2 81 [2] a9 87 [2] b5 80 [2] a9 af }

  condition:
    any of them
}