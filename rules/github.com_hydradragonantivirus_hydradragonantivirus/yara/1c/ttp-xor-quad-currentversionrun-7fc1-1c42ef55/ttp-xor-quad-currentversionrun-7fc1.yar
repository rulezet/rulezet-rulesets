rule TTP_XOR_QUAD_CurrentVersionRun_7fc1 {
  strings:
    $key_7fc1 = { 2c ae [2] 08 a0 [2] 23 8c [2] 0d ae [2] 19 b5 [2] 16 af [2] 08 b2 [2] 0a b3 [2] 11 b5 [2] 0d b2 [2] 11 9d }

  condition:
    any of them
}