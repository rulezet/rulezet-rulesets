rule TTP_XOR_QUAD_CurrentVersionRun_59dc {
  strings:
    $key_59dc = { 0a b3 [2] 2e bd [2] 05 91 [2] 2b b3 [2] 3f a8 [2] 30 b2 [2] 2e af [2] 2c ae [2] 37 a8 [2] 2b af [2] 37 80 }

  condition:
    any of them
}