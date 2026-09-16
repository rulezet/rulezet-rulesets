rule TTP_XOR_QUAD_CurrentVersionRun_c4c4 {
  strings:
    $key_c4c4 = { 97 ab [2] b3 a5 [2] 98 89 [2] b6 ab [2] a2 b0 [2] ad aa [2] b3 b7 [2] b1 b6 [2] aa b0 [2] b6 b7 [2] aa 98 }

  condition:
    any of them
}