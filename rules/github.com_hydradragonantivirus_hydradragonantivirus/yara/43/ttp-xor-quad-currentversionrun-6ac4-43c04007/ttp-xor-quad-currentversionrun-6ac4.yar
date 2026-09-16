rule TTP_XOR_QUAD_CurrentVersionRun_6ac4 {
  strings:
    $key_6ac4 = { 39 ab [2] 1d a5 [2] 36 89 [2] 18 ab [2] 0c b0 [2] 03 aa [2] 1d b7 [2] 1f b6 [2] 04 b0 [2] 18 b7 [2] 04 98 }

  condition:
    any of them
}