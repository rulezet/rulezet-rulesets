rule TTP_XOR_QUAD_CurrentVersionRun_0fc5 {
  strings:
    $key_0fc5 = { 5c aa [2] 78 a4 [2] 53 88 [2] 7d aa [2] 69 b1 [2] 66 ab [2] 78 b6 [2] 7a b7 [2] 61 b1 [2] 7d b6 [2] 61 99 }

  condition:
    any of them
}