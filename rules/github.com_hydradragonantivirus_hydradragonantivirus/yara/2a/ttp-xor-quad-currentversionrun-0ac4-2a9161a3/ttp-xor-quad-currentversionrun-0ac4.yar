rule TTP_XOR_QUAD_CurrentVersionRun_0ac4 {
  strings:
    $key_0ac4 = { 59 ab [2] 7d a5 [2] 56 89 [2] 78 ab [2] 6c b0 [2] 63 aa [2] 7d b7 [2] 7f b6 [2] 64 b0 [2] 78 b7 [2] 64 98 }

  condition:
    any of them
}