rule TTP_XOR_QUAD_CurrentVersionRun_78dc {
  strings:
    $key_78dc = { 2b b3 [2] 0f bd [2] 24 91 [2] 0a b3 [2] 1e a8 [2] 11 b2 [2] 0f af [2] 0d ae [2] 16 a8 [2] 0a af [2] 16 80 }

  condition:
    any of them
}