rule TTP_XOR_QUAD_CurrentVersionRun_6bd9 {
  strings:
    $key_6bd9 = { 38 b6 [2] 1c b8 [2] 37 94 [2] 19 b6 [2] 0d ad [2] 02 b7 [2] 1c aa [2] 1e ab [2] 05 ad [2] 19 aa [2] 05 85 }

  condition:
    any of them
}