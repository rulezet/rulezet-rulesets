rule TTP_XOR_QUAD_CurrentVersionRun_c650 {
  strings:
    $key_c650 = { 95 3f [2] b1 31 [2] 9a 1d [2] b4 3f [2] a0 24 [2] af 3e [2] b1 23 [2] b3 22 [2] a8 24 [2] b4 23 [2] a8 0c }

  condition:
    any of them
}