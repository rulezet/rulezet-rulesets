rule TTP_XOR_QUAD_CurrentVersionRun_d620 {
  strings:
    $key_d620 = { 85 4f [2] a1 41 [2] 8a 6d [2] a4 4f [2] b0 54 [2] bf 4e [2] a1 53 [2] a3 52 [2] b8 54 [2] a4 53 [2] b8 7c }

  condition:
    any of them
}