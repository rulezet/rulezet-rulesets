rule TTP_XOR_QUAD_CurrentVersionRun_e9c4 {
  strings:
    $key_e9c4 = { ba ab [2] 9e a5 [2] b5 89 [2] 9b ab [2] 8f b0 [2] 80 aa [2] 9e b7 [2] 9c b6 [2] 87 b0 [2] 9b b7 [2] 87 98 }

  condition:
    any of them
}