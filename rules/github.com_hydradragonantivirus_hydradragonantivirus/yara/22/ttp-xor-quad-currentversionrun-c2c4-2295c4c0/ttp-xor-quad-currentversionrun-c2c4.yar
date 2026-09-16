rule TTP_XOR_QUAD_CurrentVersionRun_c2c4 {
  strings:
    $key_c2c4 = { 91 ab [2] b5 a5 [2] 9e 89 [2] b0 ab [2] a4 b0 [2] ab aa [2] b5 b7 [2] b7 b6 [2] ac b0 [2] b0 b7 [2] ac 98 }

  condition:
    any of them
}