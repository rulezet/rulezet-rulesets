rule TTP_XOR_QUAD_CurrentVersionRun_7fc0 {
  strings:
    $key_7fc0 = { 2c af [2] 08 a1 [2] 23 8d [2] 0d af [2] 19 b4 [2] 16 ae [2] 08 b3 [2] 0a b2 [2] 11 b4 [2] 0d b3 [2] 11 9c }

  condition:
    any of them
}