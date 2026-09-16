rule TTP_XOR_QUAD_CurrentVersionRun_0ac5 {
  strings:
    $key_0ac5 = { 59 aa [2] 7d a4 [2] 56 88 [2] 78 aa [2] 6c b1 [2] 63 ab [2] 7d b6 [2] 7f b7 [2] 64 b1 [2] 78 b6 [2] 64 99 }

  condition:
    any of them
}