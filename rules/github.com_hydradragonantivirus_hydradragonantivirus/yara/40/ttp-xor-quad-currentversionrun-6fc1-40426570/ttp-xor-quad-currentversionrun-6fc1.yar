rule TTP_XOR_QUAD_CurrentVersionRun_6fc1 {
  strings:
    $key_6fc1 = { 3c ae [2] 18 a0 [2] 33 8c [2] 1d ae [2] 09 b5 [2] 06 af [2] 18 b2 [2] 1a b3 [2] 01 b5 [2] 1d b2 [2] 01 9d }

  condition:
    any of them
}