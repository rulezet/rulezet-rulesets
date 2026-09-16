rule TTP_XOR_QUAD_CurrentVersionRun_58c0 {
  strings:
    $key_58c0 = { 0b af [2] 2f a1 [2] 04 8d [2] 2a af [2] 3e b4 [2] 31 ae [2] 2f b3 [2] 2d b2 [2] 36 b4 [2] 2a b3 [2] 36 9c }

  condition:
    any of them
}