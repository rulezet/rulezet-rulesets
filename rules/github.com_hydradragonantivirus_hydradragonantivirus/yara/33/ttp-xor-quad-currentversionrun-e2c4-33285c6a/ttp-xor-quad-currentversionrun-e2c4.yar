rule TTP_XOR_QUAD_CurrentVersionRun_e2c4 {
  strings:
    $key_e2c4 = { b1 ab [2] 95 a5 [2] be 89 [2] 90 ab [2] 84 b0 [2] 8b aa [2] 95 b7 [2] 97 b6 [2] 8c b0 [2] 90 b7 [2] 8c 98 }

  condition:
    any of them
}