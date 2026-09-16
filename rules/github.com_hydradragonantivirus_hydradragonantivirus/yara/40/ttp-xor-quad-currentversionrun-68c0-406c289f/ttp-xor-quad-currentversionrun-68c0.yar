rule TTP_XOR_QUAD_CurrentVersionRun_68c0 {
  strings:
    $key_68c0 = { 3b af [2] 1f a1 [2] 34 8d [2] 1a af [2] 0e b4 [2] 01 ae [2] 1f b3 [2] 1d b2 [2] 06 b4 [2] 1a b3 [2] 06 9c }

  condition:
    any of them
}