rule TTP_XOR_QUAD_CurrentVersionRun_d720 {
  strings:
    $key_d720 = { 84 4f [2] a0 41 [2] 8b 6d [2] a5 4f [2] b1 54 [2] be 4e [2] a0 53 [2] a2 52 [2] b9 54 [2] a5 53 [2] b9 7c }

  condition:
    any of them
}