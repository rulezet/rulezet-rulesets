rule TTP_XOR_QUAD_CurrentVersionRun_7ac6 {
  strings:
    $key_7ac6 = { 29 a9 [2] 0d a7 [2] 26 8b [2] 08 a9 [2] 1c b2 [2] 13 a8 [2] 0d b5 [2] 0f b4 [2] 14 b2 [2] 08 b5 [2] 14 9a }

  condition:
    any of them
}