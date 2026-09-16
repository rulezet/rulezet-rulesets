rule TTP_XOR_QUAD_CurrentVersionRun_c65a {
  strings:
    $key_c65a = { 95 35 [2] b1 3b [2] 9a 17 [2] b4 35 [2] a0 2e [2] af 34 [2] b1 29 [2] b3 28 [2] a8 2e [2] b4 29 [2] a8 06 }

  condition:
    any of them
}