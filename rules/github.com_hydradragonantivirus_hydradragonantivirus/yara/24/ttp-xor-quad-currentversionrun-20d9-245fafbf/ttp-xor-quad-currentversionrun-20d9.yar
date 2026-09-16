rule TTP_XOR_QUAD_CurrentVersionRun_20d9 {
  strings:
    $key_20d9 = { 73 b6 [2] 57 b8 [2] 7c 94 [2] 52 b6 [2] 46 ad [2] 49 b7 [2] 57 aa [2] 55 ab [2] 4e ad [2] 52 aa [2] 4e 85 }

  condition:
    any of them
}