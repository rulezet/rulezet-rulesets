rule TTP_XOR_QUAD_CurrentVersionRun_d7c4 {
  strings:
    $key_d7c4 = { 84 ab [2] a0 a5 [2] 8b 89 [2] a5 ab [2] b1 b0 [2] be aa [2] a0 b7 [2] a2 b6 [2] b9 b0 [2] a5 b7 [2] b9 98 }

  condition:
    any of them
}