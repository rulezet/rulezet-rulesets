rule TTP_XOR_QUAD_CurrentVersionRun_0fd7 {
  strings:
    $key_0fd7 = { 5c b8 [2] 78 b6 [2] 53 9a [2] 7d b8 [2] 69 a3 [2] 66 b9 [2] 78 a4 [2] 7a a5 [2] 61 a3 [2] 7d a4 [2] 61 8b }

  condition:
    any of them
}