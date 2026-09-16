rule TTP_XOR_QUAD_CurrentVersionRun_d750 {
  strings:
    $key_d750 = { 84 3f [2] a0 31 [2] 8b 1d [2] a5 3f [2] b1 24 [2] be 3e [2] a0 23 [2] a2 22 [2] b9 24 [2] a5 23 [2] b9 0c }

  condition:
    any of them
}