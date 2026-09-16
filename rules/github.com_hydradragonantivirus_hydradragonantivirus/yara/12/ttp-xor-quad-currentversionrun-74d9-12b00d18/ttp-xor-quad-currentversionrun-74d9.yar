rule TTP_XOR_QUAD_CurrentVersionRun_74d9 {
  strings:
    $key_74d9 = { 27 b6 [2] 03 b8 [2] 28 94 [2] 06 b6 [2] 12 ad [2] 1d b7 [2] 03 aa [2] 01 ab [2] 1a ad [2] 06 aa [2] 1a 85 }

  condition:
    any of them
}