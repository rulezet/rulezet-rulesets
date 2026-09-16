rule TTP_XOR_QUAD_CurrentVersionRun_c3d8 {
  strings:
    $key_c3d8 = { 90 b7 [2] b4 b9 [2] 9f 95 [2] b1 b7 [2] a5 ac [2] aa b6 [2] b4 ab [2] b6 aa [2] ad ac [2] b1 ab [2] ad 84 }

  condition:
    any of them
}