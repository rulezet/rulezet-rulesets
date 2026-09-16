rule TTP_XOR_QUAD_CurrentVersionRun_c600 {
  strings:
    $key_c600 = { 95 6f [2] b1 61 [2] 9a 4d [2] b4 6f [2] a0 74 [2] af 6e [2] b1 73 [2] b3 72 [2] a8 74 [2] b4 73 [2] a8 5c }

  condition:
    any of them
}