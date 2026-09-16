rule TTP_XOR_QUAD_CurrentVersionRun_1edd {
  strings:
    $key_1edd = { 4d b2 [2] 69 bc [2] 42 90 [2] 6c b2 [2] 78 a9 [2] 77 b3 [2] 69 ae [2] 6b af [2] 70 a9 [2] 6c ae [2] 70 81 }

  condition:
    any of them
}