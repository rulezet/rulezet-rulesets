rule TTP_XOR_QUAD_CurrentVersionRun_eac4 {
  strings:
    $key_eac4 = { b9 ab [2] 9d a5 [2] b6 89 [2] 98 ab [2] 8c b0 [2] 83 aa [2] 9d b7 [2] 9f b6 [2] 84 b0 [2] 98 b7 [2] 84 98 }

  condition:
    any of them
}