rule TTP_XOR_QUAD_CurrentVersionRun_31d9 {
  strings:
    $key_31d9 = { 62 b6 [2] 46 b8 [2] 6d 94 [2] 43 b6 [2] 57 ad [2] 58 b7 [2] 46 aa [2] 44 ab [2] 5f ad [2] 43 aa [2] 5f 85 }

  condition:
    any of them
}