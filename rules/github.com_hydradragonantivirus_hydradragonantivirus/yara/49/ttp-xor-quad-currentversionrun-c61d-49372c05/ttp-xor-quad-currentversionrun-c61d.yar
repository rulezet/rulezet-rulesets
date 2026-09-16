rule TTP_XOR_QUAD_CurrentVersionRun_c61d {
  strings:
    $key_c61d = { 95 72 [2] b1 7c [2] 9a 50 [2] b4 72 [2] a0 69 [2] af 73 [2] b1 6e [2] b3 6f [2] a8 69 [2] b4 6e [2] a8 41 }

  condition:
    any of them
}