rule TTP_XOR_QUAD_CurrentVersionRun_45d9 {
  strings:
    $key_45d9 = { 16 b6 [2] 32 b8 [2] 19 94 [2] 37 b6 [2] 23 ad [2] 2c b7 [2] 32 aa [2] 30 ab [2] 2b ad [2] 37 aa [2] 2b 85 }

  condition:
    any of them
}