rule TTP_XOR_QUAD_CurrentVersionRun_3bd9 {
  strings:
    $key_3bd9 = { 68 b6 [2] 4c b8 [2] 67 94 [2] 49 b6 [2] 5d ad [2] 52 b7 [2] 4c aa [2] 4e ab [2] 55 ad [2] 49 aa [2] 55 85 }

  condition:
    any of them
}