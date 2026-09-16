rule TTP_XOR_QUAD_CurrentVersionRun_6ac5 {
  strings:
    $key_6ac5 = { 39 aa [2] 1d a4 [2] 36 88 [2] 18 aa [2] 0c b1 [2] 03 ab [2] 1d b6 [2] 1f b7 [2] 04 b1 [2] 18 b6 [2] 04 99 }

  condition:
    any of them
}