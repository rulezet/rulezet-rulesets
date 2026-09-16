rule TTP_XOR_QUAD_CurrentVersionRun_c66d {
  strings:
    $key_c66d = { 95 02 [2] b1 0c [2] 9a 20 [2] b4 02 [2] a0 19 [2] af 03 [2] b1 1e [2] b3 1f [2] a8 19 [2] b4 1e [2] a8 31 }

  condition:
    any of them
}