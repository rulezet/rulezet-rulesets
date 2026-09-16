rule TTP_XOR_QUAD_CurrentVersionRun_16d9 {
  strings:
    $key_16d9 = { 45 b6 [2] 61 b8 [2] 4a 94 [2] 64 b6 [2] 70 ad [2] 7f b7 [2] 61 aa [2] 63 ab [2] 78 ad [2] 64 aa [2] 78 85 }

  condition:
    any of them
}