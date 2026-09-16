rule TTP_XOR_QUAD_CurrentVersionRun_d66b {
  strings:
    $key_d66b = { 85 04 [2] a1 0a [2] 8a 26 [2] a4 04 [2] b0 1f [2] bf 05 [2] a1 18 [2] a3 19 [2] b8 1f [2] a4 18 [2] b8 37 }

  condition:
    any of them
}