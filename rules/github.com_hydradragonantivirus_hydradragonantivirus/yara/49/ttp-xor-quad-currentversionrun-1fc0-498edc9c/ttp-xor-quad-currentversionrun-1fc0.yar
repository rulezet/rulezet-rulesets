rule TTP_XOR_QUAD_CurrentVersionRun_1fc0 {
  strings:
    $key_1fc0 = { 4c af [2] 68 a1 [2] 43 8d [2] 6d af [2] 79 b4 [2] 76 ae [2] 68 b3 [2] 6a b2 [2] 71 b4 [2] 6d b3 [2] 71 9c }

  condition:
    any of them
}