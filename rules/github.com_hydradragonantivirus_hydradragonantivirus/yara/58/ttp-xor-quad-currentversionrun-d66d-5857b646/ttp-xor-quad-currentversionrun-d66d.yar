rule TTP_XOR_QUAD_CurrentVersionRun_d66d {
  strings:
    $key_d66d = { 85 02 [2] a1 0c [2] 8a 20 [2] a4 02 [2] b0 19 [2] bf 03 [2] a1 1e [2] a3 1f [2] b8 19 [2] a4 1e [2] b8 31 }

  condition:
    any of them
}