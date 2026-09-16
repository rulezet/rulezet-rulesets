rule TTP_XOR_QUAD_CurrentVersionRun_2fc0 {
  strings:
    $key_2fc0 = { 7c af [2] 58 a1 [2] 73 8d [2] 5d af [2] 49 b4 [2] 46 ae [2] 58 b3 [2] 5a b2 [2] 41 b4 [2] 5d b3 [2] 41 9c }

  condition:
    any of them
}