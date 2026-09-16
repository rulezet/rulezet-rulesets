rule TTP_XOR_QUAD_CurrentVersionRun_c66c {
  strings:
    $key_c66c = { 95 03 [2] b1 0d [2] 9a 21 [2] b4 03 [2] a0 18 [2] af 02 [2] b1 1f [2] b3 1e [2] a8 18 [2] b4 1f [2] a8 30 }

  condition:
    any of them
}