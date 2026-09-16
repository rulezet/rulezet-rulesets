rule TTP_XOR_QUAD_CurrentVersionRun_6fc5 {
  strings:
    $key_6fc5 = { 3c aa [2] 18 a4 [2] 33 88 [2] 1d aa [2] 09 b1 [2] 06 ab [2] 18 b6 [2] 1a b7 [2] 01 b1 [2] 1d b6 [2] 01 99 }

  condition:
    any of them
}