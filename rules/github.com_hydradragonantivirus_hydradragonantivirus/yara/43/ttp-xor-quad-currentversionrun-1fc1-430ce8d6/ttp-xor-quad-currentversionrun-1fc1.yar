rule TTP_XOR_QUAD_CurrentVersionRun_1fc1 {
  strings:
    $key_1fc1 = { 4c ae [2] 68 a0 [2] 43 8c [2] 6d ae [2] 79 b5 [2] 76 af [2] 68 b2 [2] 6a b3 [2] 71 b5 [2] 6d b2 [2] 71 9d }

  condition:
    any of them
}