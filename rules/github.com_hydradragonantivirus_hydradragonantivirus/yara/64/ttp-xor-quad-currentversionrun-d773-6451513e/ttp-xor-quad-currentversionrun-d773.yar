rule TTP_XOR_QUAD_CurrentVersionRun_d773 {
  strings:
    $key_d773 = { 84 1c [2] a0 12 [2] 8b 3e [2] a5 1c [2] b1 07 [2] be 1d [2] a0 00 [2] a2 01 [2] b9 07 [2] a5 00 [2] b9 2f }

  condition:
    any of them
}