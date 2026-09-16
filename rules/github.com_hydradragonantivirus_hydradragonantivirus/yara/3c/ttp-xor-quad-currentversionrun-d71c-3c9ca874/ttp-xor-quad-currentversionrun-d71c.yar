rule TTP_XOR_QUAD_CurrentVersionRun_d71c {
  strings:
    $key_d71c = { 84 73 [2] a0 7d [2] 8b 51 [2] a5 73 [2] b1 68 [2] be 72 [2] a0 6f [2] a2 6e [2] b9 68 [2] a5 6f [2] b9 40 }

  condition:
    any of them
}