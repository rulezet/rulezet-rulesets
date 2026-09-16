rule TTP_XOR_QUAD_CurrentVersionRun_d636 {
  strings:
    $key_d636 = { 85 59 [2] a1 57 [2] 8a 7b [2] a4 59 [2] b0 42 [2] bf 58 [2] a1 45 [2] a3 44 [2] b8 42 [2] a4 45 [2] b8 6a }

  condition:
    any of them
}