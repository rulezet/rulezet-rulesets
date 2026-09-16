rule TTP_XOR_QUAD_CurrentVersionRun_1ac1 {
  strings:
    $key_1ac1 = { 49 ae [2] 6d a0 [2] 46 8c [2] 68 ae [2] 7c b5 [2] 73 af [2] 6d b2 [2] 6f b3 [2] 74 b5 [2] 68 b2 [2] 74 9d }

  condition:
    any of them
}