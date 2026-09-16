rule TTP_XOR_QUAD_CurrentVersionRun_6edd {
  strings:
    $key_6edd = { 3d b2 [2] 19 bc [2] 32 90 [2] 1c b2 [2] 08 a9 [2] 07 b3 [2] 19 ae [2] 1b af [2] 00 a9 [2] 1c ae [2] 00 81 }

  condition:
    any of them
}