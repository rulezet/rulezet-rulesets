rule TTP_XOR_QUAD_CurrentVersionRun_e9dc {
  strings:
    $key_e9dc = { ba b3 [2] 9e bd [2] b5 91 [2] 9b b3 [2] 8f a8 [2] 80 b2 [2] 9e af [2] 9c ae [2] 87 a8 [2] 9b af [2] 87 80 }

  condition:
    any of them
}