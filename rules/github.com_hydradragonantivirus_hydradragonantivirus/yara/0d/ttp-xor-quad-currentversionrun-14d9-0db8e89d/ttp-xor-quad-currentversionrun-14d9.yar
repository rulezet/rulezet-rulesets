rule TTP_XOR_QUAD_CurrentVersionRun_14d9 {
  strings:
    $key_14d9 = { 47 b6 [2] 63 b8 [2] 48 94 [2] 66 b6 [2] 72 ad [2] 7d b7 [2] 63 aa [2] 61 ab [2] 7a ad [2] 66 aa [2] 7a 85 }

  condition:
    any of them
}