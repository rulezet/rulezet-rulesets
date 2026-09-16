rule TTP_XOR_QUAD_CurrentVersionRun_68dc {
  strings:
    $key_68dc = { 3b b3 [2] 1f bd [2] 34 91 [2] 1a b3 [2] 0e a8 [2] 01 b2 [2] 1f af [2] 1d ae [2] 06 a8 [2] 1a af [2] 06 80 }

  condition:
    any of them
}