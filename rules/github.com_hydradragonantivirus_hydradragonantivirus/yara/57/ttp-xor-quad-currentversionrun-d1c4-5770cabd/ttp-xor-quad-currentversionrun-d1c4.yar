rule TTP_XOR_QUAD_CurrentVersionRun_d1c4 {
  strings:
    $key_d1c4 = { 82 ab [2] a6 a5 [2] 8d 89 [2] a3 ab [2] b7 b0 [2] b8 aa [2] a6 b7 [2] a4 b6 [2] bf b0 [2] a3 b7 [2] bf 98 }

  condition:
    any of them
}