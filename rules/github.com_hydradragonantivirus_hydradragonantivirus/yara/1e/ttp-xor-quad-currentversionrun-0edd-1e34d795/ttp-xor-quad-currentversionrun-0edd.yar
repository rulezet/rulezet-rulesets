rule TTP_XOR_QUAD_CurrentVersionRun_0edd {
  strings:
    $key_0edd = { 5d b2 [2] 79 bc [2] 52 90 [2] 7c b2 [2] 68 a9 [2] 67 b3 [2] 79 ae [2] 7b af [2] 60 a9 [2] 7c ae [2] 60 81 }

  condition:
    any of them
}