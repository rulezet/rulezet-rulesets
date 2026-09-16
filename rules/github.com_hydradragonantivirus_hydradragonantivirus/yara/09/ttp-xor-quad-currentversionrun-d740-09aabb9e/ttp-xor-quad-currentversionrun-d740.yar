rule TTP_XOR_QUAD_CurrentVersionRun_d740 {
  strings:
    $key_d740 = { 84 2f [2] a0 21 [2] 8b 0d [2] a5 2f [2] b1 34 [2] be 2e [2] a0 33 [2] a2 32 [2] b9 34 [2] a5 33 [2] b9 1c }

  condition:
    any of them
}