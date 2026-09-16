rule TTP_XOR_QUAD_CurrentVersionRun_4bd9 {
  strings:
    $key_4bd9 = { 18 b6 [2] 3c b8 [2] 17 94 [2] 39 b6 [2] 2d ad [2] 22 b7 [2] 3c aa [2] 3e ab [2] 25 ad [2] 39 aa [2] 25 85 }

  condition:
    any of them
}