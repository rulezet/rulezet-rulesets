rule TTP_XOR_QUAD_CurrentVersionRun_d71d {
  strings:
    $key_d71d = { 84 72 [2] a0 7c [2] 8b 50 [2] a5 72 [2] b1 69 [2] be 73 [2] a0 6e [2] a2 6f [2] b9 69 [2] a5 6e [2] b9 41 }

  condition:
    any of them
}