rule TTP_XOR_QUAD_CurrentVersionRun_c63a {
  strings:
    $key_c63a = { 95 55 [2] b1 5b [2] 9a 77 [2] b4 55 [2] a0 4e [2] af 54 [2] b1 49 [2] b3 48 [2] a8 4e [2] b4 49 [2] a8 66 }

  condition:
    any of them
}