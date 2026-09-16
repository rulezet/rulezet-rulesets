rule TTP_XOR_QUAD_CurrentVersionRun_c7c4 {
  strings:
    $key_c7c4 = { 94 ab [2] b0 a5 [2] 9b 89 [2] b5 ab [2] a1 b0 [2] ae aa [2] b0 b7 [2] b2 b6 [2] a9 b0 [2] b5 b7 [2] a9 98 }

  condition:
    any of them
}