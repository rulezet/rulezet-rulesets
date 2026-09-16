rule TTP_XOR_QUAD_CurrentVersionRun_d656 {
  strings:
    $key_d656 = { 85 39 [2] a1 37 [2] 8a 1b [2] a4 39 [2] b0 22 [2] bf 38 [2] a1 25 [2] a3 24 [2] b8 22 [2] a4 25 [2] b8 0a }

  condition:
    any of them
}