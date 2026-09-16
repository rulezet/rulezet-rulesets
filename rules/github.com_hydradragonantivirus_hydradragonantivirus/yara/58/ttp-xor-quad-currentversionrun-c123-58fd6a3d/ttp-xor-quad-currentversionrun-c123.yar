rule TTP_XOR_QUAD_CurrentVersionRun_c123 {
  strings:
    $key_c123 = { 92 4c [2] b6 42 [2] 9d 6e [2] b3 4c [2] a7 57 [2] a8 4d [2] b6 50 [2] b4 51 [2] af 57 [2] b3 50 [2] af 7f }

  condition:
    any of them
}