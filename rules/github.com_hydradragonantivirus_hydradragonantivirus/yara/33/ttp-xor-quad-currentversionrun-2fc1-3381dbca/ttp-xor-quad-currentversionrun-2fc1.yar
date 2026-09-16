rule TTP_XOR_QUAD_CurrentVersionRun_2fc1 {
  strings:
    $key_2fc1 = { 7c ae [2] 58 a0 [2] 73 8c [2] 5d ae [2] 49 b5 [2] 46 af [2] 58 b2 [2] 5a b3 [2] 41 b5 [2] 5d b2 [2] 41 9d }

  condition:
    any of them
}