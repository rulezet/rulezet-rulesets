rule TTP_XOR_QUAD_CurrentVersionRun_72c4 {
  strings:
    $key_72c4 = { 21 ab [2] 05 a5 [2] 2e 89 [2] 00 ab [2] 14 b0 [2] 1b aa [2] 05 b7 [2] 07 b6 [2] 1c b0 [2] 00 b7 [2] 1c 98 }

  condition:
    any of them
}