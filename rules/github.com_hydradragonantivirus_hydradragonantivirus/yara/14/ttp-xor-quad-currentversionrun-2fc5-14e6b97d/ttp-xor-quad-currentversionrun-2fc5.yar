rule TTP_XOR_QUAD_CurrentVersionRun_2fc5 {
  strings:
    $key_2fc5 = { 7c aa [2] 58 a4 [2] 73 88 [2] 5d aa [2] 49 b1 [2] 46 ab [2] 58 b6 [2] 5a b7 [2] 41 b1 [2] 5d b6 [2] 41 99 }

  condition:
    any of them
}