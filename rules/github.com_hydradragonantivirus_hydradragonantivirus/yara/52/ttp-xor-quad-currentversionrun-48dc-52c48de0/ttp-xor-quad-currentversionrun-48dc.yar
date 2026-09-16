rule TTP_XOR_QUAD_CurrentVersionRun_48dc {
  strings:
    $key_48dc = { 1b b3 [2] 3f bd [2] 14 91 [2] 3a b3 [2] 2e a8 [2] 21 b2 [2] 3f af [2] 3d ae [2] 26 a8 [2] 3a af [2] 26 80 }

  condition:
    any of them
}