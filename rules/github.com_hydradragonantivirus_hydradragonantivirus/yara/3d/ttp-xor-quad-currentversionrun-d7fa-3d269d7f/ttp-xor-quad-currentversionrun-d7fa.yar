rule TTP_XOR_QUAD_CurrentVersionRun_d7fa {
  strings:
    $key_d7fa = { 84 95 [2] a0 9b [2] 8b b7 [2] a5 95 [2] b1 8e [2] be 94 [2] a0 89 [2] a2 88 [2] b9 8e [2] a5 89 [2] b9 a6 }

  condition:
    any of them
}