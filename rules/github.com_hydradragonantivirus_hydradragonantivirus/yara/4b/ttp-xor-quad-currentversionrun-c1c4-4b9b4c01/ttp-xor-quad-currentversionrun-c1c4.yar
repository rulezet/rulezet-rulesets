rule TTP_XOR_QUAD_CurrentVersionRun_c1c4 {
  strings:
    $key_c1c4 = { 92 ab [2] b6 a5 [2] 9d 89 [2] b3 ab [2] a7 b0 [2] a8 aa [2] b6 b7 [2] b4 b6 [2] af b0 [2] b3 b7 [2] af 98 }

  condition:
    any of them
}