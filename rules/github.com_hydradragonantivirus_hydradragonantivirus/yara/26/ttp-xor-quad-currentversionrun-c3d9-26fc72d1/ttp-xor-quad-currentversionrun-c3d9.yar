rule TTP_XOR_QUAD_CurrentVersionRun_c3d9 {
  strings:
    $key_c3d9 = { 90 b6 [2] b4 b8 [2] 9f 94 [2] b1 b6 [2] a5 ad [2] aa b7 [2] b4 aa [2] b6 ab [2] ad ad [2] b1 aa [2] ad 85 }

  condition:
    any of them
}