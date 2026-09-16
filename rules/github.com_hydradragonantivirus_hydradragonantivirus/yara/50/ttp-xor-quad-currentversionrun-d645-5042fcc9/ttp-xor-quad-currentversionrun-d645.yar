rule TTP_XOR_QUAD_CurrentVersionRun_d645 {
  strings:
    $key_d645 = { 85 2a [2] a1 24 [2] 8a 08 [2] a4 2a [2] b0 31 [2] bf 2b [2] a1 36 [2] a3 37 [2] b8 31 [2] a4 36 [2] b8 19 }

  condition:
    any of them
}