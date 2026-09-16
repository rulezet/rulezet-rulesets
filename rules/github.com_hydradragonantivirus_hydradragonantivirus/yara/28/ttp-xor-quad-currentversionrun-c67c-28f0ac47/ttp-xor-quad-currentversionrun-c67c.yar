rule TTP_XOR_QUAD_CurrentVersionRun_c67c {
  strings:
    $key_c67c = { 95 13 [2] b1 1d [2] 9a 31 [2] b4 13 [2] a0 08 [2] af 12 [2] b1 0f [2] b3 0e [2] a8 08 [2] b4 0f [2] a8 20 }

  condition:
    any of them
}