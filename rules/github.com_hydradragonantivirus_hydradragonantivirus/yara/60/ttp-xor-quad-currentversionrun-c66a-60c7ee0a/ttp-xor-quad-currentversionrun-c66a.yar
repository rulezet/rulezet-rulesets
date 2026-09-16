rule TTP_XOR_QUAD_CurrentVersionRun_c66a {
  strings:
    $key_c66a = { 95 05 [2] b1 0b [2] 9a 27 [2] b4 05 [2] a0 1e [2] af 04 [2] b1 19 [2] b3 18 [2] a8 1e [2] b4 19 [2] a8 36 }

  condition:
    any of them
}