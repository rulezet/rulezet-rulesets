rule TTP_XOR_QUAD_CurrentVersionRun_c61c {
  strings:
    $key_c61c = { 95 73 [2] b1 7d [2] 9a 51 [2] b4 73 [2] a0 68 [2] af 72 [2] b1 6f [2] b3 6e [2] a8 68 [2] b4 6f [2] a8 40 }

  condition:
    any of them
}