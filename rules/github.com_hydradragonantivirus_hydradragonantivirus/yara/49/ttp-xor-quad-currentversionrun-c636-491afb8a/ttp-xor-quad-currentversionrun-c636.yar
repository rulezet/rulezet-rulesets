rule TTP_XOR_QUAD_CurrentVersionRun_c636 {
  strings:
    $key_c636 = { 95 59 [2] b1 57 [2] 9a 7b [2] b4 59 [2] a0 42 [2] af 58 [2] b1 45 [2] b3 44 [2] a8 42 [2] b4 45 [2] a8 6a }

  condition:
    any of them
}