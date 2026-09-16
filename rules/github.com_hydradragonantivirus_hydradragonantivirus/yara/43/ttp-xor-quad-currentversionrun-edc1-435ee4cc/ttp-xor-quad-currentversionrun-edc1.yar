rule TTP_XOR_QUAD_CurrentVersionRun_edc1 {
  strings:
    $key_edc1 = { be ae [2] 9a a0 [2] b1 8c [2] 9f ae [2] 8b b5 [2] 84 af [2] 9a b2 [2] 98 b3 [2] 83 b5 [2] 9f b2 [2] 83 9d }

  condition:
    any of them
}