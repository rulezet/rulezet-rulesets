rule TTP_XOR_QUAD_CurrentVersionRun_d67a {
  strings:
    $key_d67a = { 85 15 [2] a1 1b [2] 8a 37 [2] a4 15 [2] b0 0e [2] bf 14 [2] a1 09 [2] a3 08 [2] b8 0e [2] a4 09 [2] b8 26 }

  condition:
    any of them
}