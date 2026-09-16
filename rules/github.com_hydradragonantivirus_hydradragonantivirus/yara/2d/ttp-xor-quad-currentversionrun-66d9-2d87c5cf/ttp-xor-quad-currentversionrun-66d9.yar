rule TTP_XOR_QUAD_CurrentVersionRun_66d9 {
  strings:
    $key_66d9 = { 35 b6 [2] 11 b8 [2] 3a 94 [2] 14 b6 [2] 00 ad [2] 0f b7 [2] 11 aa [2] 13 ab [2] 08 ad [2] 14 aa [2] 08 85 }

  condition:
    any of them
}