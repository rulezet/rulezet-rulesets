rule TTP_XOR_QUAD_CurrentVersionRun_d606 {
  strings:
    $key_d606 = { 85 69 [2] a1 67 [2] 8a 4b [2] a4 69 [2] b0 72 [2] bf 68 [2] a1 75 [2] a3 74 [2] b8 72 [2] a4 75 [2] b8 5a }

  condition:
    any of them
}