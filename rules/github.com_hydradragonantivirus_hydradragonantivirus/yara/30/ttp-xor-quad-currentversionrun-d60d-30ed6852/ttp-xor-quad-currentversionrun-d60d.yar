rule TTP_XOR_QUAD_CurrentVersionRun_d60d {
  strings:
    $key_d60d = { 85 62 [2] a1 6c [2] 8a 40 [2] a4 62 [2] b0 79 [2] bf 63 [2] a1 7e [2] a3 7f [2] b8 79 [2] a4 7e [2] b8 51 }

  condition:
    any of them
}