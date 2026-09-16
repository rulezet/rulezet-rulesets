rule TTP_XOR_QUAD_CurrentVersionRun_c100 {
  strings:
    $key_c100 = { 92 6f [2] b6 61 [2] 9d 4d [2] b3 6f [2] a7 74 [2] a8 6e [2] b6 73 [2] b4 72 [2] af 74 [2] b3 73 [2] af 5c }

  condition:
    any of them
}