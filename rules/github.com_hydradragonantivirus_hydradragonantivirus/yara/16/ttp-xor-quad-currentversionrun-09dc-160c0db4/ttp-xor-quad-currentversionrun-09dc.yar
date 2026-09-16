rule TTP_XOR_QUAD_CurrentVersionRun_09dc {
  strings:
    $key_09dc = { 5a b3 [2] 7e bd [2] 55 91 [2] 7b b3 [2] 6f a8 [2] 60 b2 [2] 7e af [2] 7c ae [2] 67 a8 [2] 7b af [2] 67 80 }

  condition:
    any of them
}