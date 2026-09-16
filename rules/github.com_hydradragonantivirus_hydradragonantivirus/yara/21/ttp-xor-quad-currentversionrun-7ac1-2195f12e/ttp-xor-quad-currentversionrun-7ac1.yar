rule TTP_XOR_QUAD_CurrentVersionRun_7ac1 {
  strings:
    $key_7ac1 = { 29 ae [2] 0d a0 [2] 26 8c [2] 08 ae [2] 1c b5 [2] 13 af [2] 0d b2 [2] 0f b3 [2] 14 b5 [2] 08 b2 [2] 14 9d }

  condition:
    any of them
}