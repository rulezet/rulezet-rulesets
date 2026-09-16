rule TTP_XOR_QUAD_CurrentVersionRun_28dc {
  strings:
    $key_28dc = { 7b b3 [2] 5f bd [2] 74 91 [2] 5a b3 [2] 4e a8 [2] 41 b2 [2] 5f af [2] 5d ae [2] 46 a8 [2] 5a af [2] 46 80 }

  condition:
    any of them
}