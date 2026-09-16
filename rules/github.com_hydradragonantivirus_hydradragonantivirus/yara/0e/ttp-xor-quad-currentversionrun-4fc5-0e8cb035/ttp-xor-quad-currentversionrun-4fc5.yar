rule TTP_XOR_QUAD_CurrentVersionRun_4fc5 {
  strings:
    $key_4fc5 = { 1c aa [2] 38 a4 [2] 13 88 [2] 3d aa [2] 29 b1 [2] 26 ab [2] 38 b6 [2] 3a b7 [2] 21 b1 [2] 3d b6 [2] 21 99 }

  condition:
    any of them
}