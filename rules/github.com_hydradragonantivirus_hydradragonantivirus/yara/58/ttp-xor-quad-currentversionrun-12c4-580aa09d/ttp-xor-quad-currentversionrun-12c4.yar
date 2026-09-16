rule TTP_XOR_QUAD_CurrentVersionRun_12c4 {
  strings:
    $key_12c4 = { 41 ab [2] 65 a5 [2] 4e 89 [2] 60 ab [2] 74 b0 [2] 7b aa [2] 65 b7 [2] 67 b6 [2] 7c b0 [2] 60 b7 [2] 7c 98 }

  condition:
    any of them
}