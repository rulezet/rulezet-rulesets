rule TTP_XOR_QUAD_CurrentVersionRun_38dc {
  strings:
    $key_38dc = { 6b b3 [2] 4f bd [2] 64 91 [2] 4a b3 [2] 5e a8 [2] 51 b2 [2] 4f af [2] 4d ae [2] 56 a8 [2] 4a af [2] 56 80 }

  condition:
    any of them
}