rule TTP_XOR_QUAD_CurrentVersionRun_34d7 {
  strings:
    $key_34d7 = { 67 b8 [2] 43 b6 [2] 68 9a [2] 46 b8 [2] 52 a3 [2] 5d b9 [2] 43 a4 [2] 41 a5 [2] 5a a3 [2] 46 a4 [2] 5a 8b }

  condition:
    any of them
}