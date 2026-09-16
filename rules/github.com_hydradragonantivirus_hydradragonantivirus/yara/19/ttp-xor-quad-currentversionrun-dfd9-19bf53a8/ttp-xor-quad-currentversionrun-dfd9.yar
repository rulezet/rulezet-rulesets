rule TTP_XOR_QUAD_CurrentVersionRun_dfd9 {
  strings:
    $key_dfd9 = { 8c b6 [2] a8 b8 [2] 83 94 [2] ad b6 [2] b9 ad [2] b6 b7 [2] a8 aa [2] aa ab [2] b1 ad [2] ad aa [2] b1 85 }

  condition:
    any of them
}