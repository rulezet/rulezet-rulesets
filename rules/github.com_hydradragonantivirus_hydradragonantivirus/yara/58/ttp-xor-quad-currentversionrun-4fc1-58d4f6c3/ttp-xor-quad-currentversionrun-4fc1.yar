rule TTP_XOR_QUAD_CurrentVersionRun_4fc1 {
  strings:
    $key_4fc1 = { 1c ae [2] 38 a0 [2] 13 8c [2] 3d ae [2] 29 b5 [2] 26 af [2] 38 b2 [2] 3a b3 [2] 21 b5 [2] 3d b2 [2] 21 9d }

  condition:
    any of them
}