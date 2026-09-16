rule TTP_XOR_QUAD_CurrentVersionRun_22d9 {
  strings:
    $key_22d9 = { 71 b6 [2] 55 b8 [2] 7e 94 [2] 50 b6 [2] 44 ad [2] 4b b7 [2] 55 aa [2] 57 ab [2] 4c ad [2] 50 aa [2] 4c 85 }

  condition:
    any of them
}