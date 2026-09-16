rule TTP_XOR_QUAD_CurrentVersionRun_d1c5 {
  strings:
    $key_d1c5 = { 82 aa [2] a6 a4 [2] 8d 88 [2] a3 aa [2] b7 b1 [2] b8 ab [2] a6 b6 [2] a4 b7 [2] bf b1 [2] a3 b6 [2] bf 99 }

  condition:
    any of them
}