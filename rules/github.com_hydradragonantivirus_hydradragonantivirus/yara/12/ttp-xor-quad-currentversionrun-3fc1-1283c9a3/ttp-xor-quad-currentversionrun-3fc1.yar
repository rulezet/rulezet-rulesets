rule TTP_XOR_QUAD_CurrentVersionRun_3fc1 {
  strings:
    $key_3fc1 = { 6c ae [2] 48 a0 [2] 63 8c [2] 4d ae [2] 59 b5 [2] 56 af [2] 48 b2 [2] 4a b3 [2] 51 b5 [2] 4d b2 [2] 51 9d }

  condition:
    any of them
}