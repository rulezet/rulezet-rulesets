rule TTP_XOR_QUAD_CurrentVersionRun_03c0 {
  strings:
    $key_03c0 = { 50 af [2] 74 a1 [2] 5f 8d [2] 71 af [2] 65 b4 [2] 6a ae [2] 74 b3 [2] 76 b2 [2] 6d b4 [2] 71 b3 [2] 6d 9c }

  condition:
    any of them
}