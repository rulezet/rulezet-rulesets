rule TTP_XOR_QUAD_CurrentVersionRun_28c0 {
  strings:
    $key_28c0 = { 7b af [2] 5f a1 [2] 74 8d [2] 5a af [2] 4e b4 [2] 41 ae [2] 5f b3 [2] 5d b2 [2] 46 b4 [2] 5a b3 [2] 46 9c }

  condition:
    any of them
}