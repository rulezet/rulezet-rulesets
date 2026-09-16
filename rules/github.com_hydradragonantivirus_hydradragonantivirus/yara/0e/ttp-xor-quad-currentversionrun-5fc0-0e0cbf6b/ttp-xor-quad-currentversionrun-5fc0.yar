rule TTP_XOR_QUAD_CurrentVersionRun_5fc0 {
  strings:
    $key_5fc0 = { 0c af [2] 28 a1 [2] 03 8d [2] 2d af [2] 39 b4 [2] 36 ae [2] 28 b3 [2] 2a b2 [2] 31 b4 [2] 2d b3 [2] 31 9c }

  condition:
    any of them
}