rule TTP_XOR_QUAD_CurrentVersionRun_d62b {
  strings:
    $key_d62b = { 85 44 [2] a1 4a [2] 8a 66 [2] a4 44 [2] b0 5f [2] bf 45 [2] a1 58 [2] a3 59 [2] b8 5f [2] a4 58 [2] b8 77 }

  condition:
    any of them
}