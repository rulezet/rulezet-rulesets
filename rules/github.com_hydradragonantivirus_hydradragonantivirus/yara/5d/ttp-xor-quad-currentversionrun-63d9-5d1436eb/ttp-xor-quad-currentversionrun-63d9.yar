rule TTP_XOR_QUAD_CurrentVersionRun_63d9 {
  strings:
    $key_63d9 = { 30 b6 [2] 14 b8 [2] 3f 94 [2] 11 b6 [2] 05 ad [2] 0a b7 [2] 14 aa [2] 16 ab [2] 0d ad [2] 11 aa [2] 0d 85 }

  condition:
    any of them
}