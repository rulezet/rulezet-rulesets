rule TTP_XOR_QUAD_CurrentVersionRun_d7fd {
  strings:
    $key_d7fd = { 84 92 [2] a0 9c [2] 8b b0 [2] a5 92 [2] b1 89 [2] be 93 [2] a0 8e [2] a2 8f [2] b9 89 [2] a5 8e [2] b9 a1 }

  condition:
    any of them
}