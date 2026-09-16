rule TTP_XOR_QUAD_CurrentVersionRun_1ac4 {
  strings:
    $key_1ac4 = { 49 ab [2] 6d a5 [2] 46 89 [2] 68 ab [2] 7c b0 [2] 73 aa [2] 6d b7 [2] 6f b6 [2] 74 b0 [2] 68 b7 [2] 74 98 }

  condition:
    any of them
}