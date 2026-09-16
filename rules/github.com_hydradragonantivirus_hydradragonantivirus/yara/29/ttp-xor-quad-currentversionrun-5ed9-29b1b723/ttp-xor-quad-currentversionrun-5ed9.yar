rule TTP_XOR_QUAD_CurrentVersionRun_5ed9 {
  strings:
    $key_5ed9 = { 0d b6 [2] 29 b8 [2] 02 94 [2] 2c b6 [2] 38 ad [2] 37 b7 [2] 29 aa [2] 2b ab [2] 30 ad [2] 2c aa [2] 30 85 }

  condition:
    any of them
}