rule TTP_XOR_QUAD_CurrentVersionRun_18dc {
  strings:
    $key_18dc = { 4b b3 [2] 6f bd [2] 44 91 [2] 6a b3 [2] 7e a8 [2] 71 b2 [2] 6f af [2] 6d ae [2] 76 a8 [2] 6a af [2] 76 80 }

  condition:
    any of them
}