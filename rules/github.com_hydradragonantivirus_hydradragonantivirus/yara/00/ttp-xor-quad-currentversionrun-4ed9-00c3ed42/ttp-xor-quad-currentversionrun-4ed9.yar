rule TTP_XOR_QUAD_CurrentVersionRun_4ed9 {
  strings:
    $key_4ed9 = { 1d b6 [2] 39 b8 [2] 12 94 [2] 3c b6 [2] 28 ad [2] 27 b7 [2] 39 aa [2] 3b ab [2] 20 ad [2] 3c aa [2] 20 85 }

  condition:
    any of them
}