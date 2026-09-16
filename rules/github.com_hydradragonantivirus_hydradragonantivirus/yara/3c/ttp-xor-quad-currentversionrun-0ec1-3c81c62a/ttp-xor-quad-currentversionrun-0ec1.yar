rule TTP_XOR_QUAD_CurrentVersionRun_0ec1 {
  strings:
    $key_0ec1 = { 5d ae [2] 79 a0 [2] 52 8c [2] 7c ae [2] 68 b5 [2] 67 af [2] 79 b2 [2] 7b b3 [2] 60 b5 [2] 7c b2 [2] 60 9d }

  condition:
    any of them
}