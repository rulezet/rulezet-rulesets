rule TTP_XOR_QUAD_CurrentVersionRun_26d9 {
  strings:
    $key_26d9 = { 75 b6 [2] 51 b8 [2] 7a 94 [2] 54 b6 [2] 40 ad [2] 4f b7 [2] 51 aa [2] 53 ab [2] 48 ad [2] 54 aa [2] 48 85 }

  condition:
    any of them
}