rule TTP_XOR_QUAD_CurrentVersionRun_d75a {
  strings:
    $key_d75a = { 84 35 [2] a0 3b [2] 8b 17 [2] a5 35 [2] b1 2e [2] be 34 [2] a0 29 [2] a2 28 [2] b9 2e [2] a5 29 [2] b9 06 }

  condition:
    any of them
}