rule TTP_XOR_QUAD_CurrentVersionRun_04d9 {
  strings:
    $key_04d9 = { 57 b6 [2] 73 b8 [2] 58 94 [2] 76 b6 [2] 62 ad [2] 6d b7 [2] 73 aa [2] 71 ab [2] 6a ad [2] 76 aa [2] 6a 85 }

  condition:
    any of them
}