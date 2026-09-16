rule TTP_XOR_QUAD_CurrentVersionRun_c611 {
  strings:
    $key_c611 = { 95 7e [2] b1 70 [2] 9a 5c [2] b4 7e [2] a0 65 [2] af 7f [2] b1 62 [2] b3 63 [2] a8 65 [2] b4 62 [2] a8 4d }

  condition:
    any of them
}