rule TTP_XOR_QUAD_CurrentVersionRun_1ec1 {
  strings:
    $key_1ec1 = { 4d ae [2] 69 a0 [2] 42 8c [2] 6c ae [2] 78 b5 [2] 77 af [2] 69 b2 [2] 6b b3 [2] 70 b5 [2] 6c b2 [2] 70 9d }

  condition:
    any of them
}