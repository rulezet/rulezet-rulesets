rule TTP_XOR_QUAD_CurrentVersionRun_0fc7 {
  strings:
    $key_0fc7 = { 5c a8 [2] 78 a6 [2] 53 8a [2] 7d a8 [2] 69 b3 [2] 66 a9 [2] 78 b4 [2] 7a b5 [2] 61 b3 [2] 7d b4 [2] 61 9b }

  condition:
    any of them
}