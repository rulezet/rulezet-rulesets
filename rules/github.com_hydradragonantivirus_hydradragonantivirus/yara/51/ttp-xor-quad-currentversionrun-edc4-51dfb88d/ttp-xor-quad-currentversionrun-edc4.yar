rule TTP_XOR_QUAD_CurrentVersionRun_edc4 {
  strings:
    $key_edc4 = { be ab [2] 9a a5 [2] b1 89 [2] 9f ab [2] 8b b0 [2] 84 aa [2] 9a b7 [2] 98 b6 [2] 83 b0 [2] 9f b7 [2] 83 98 }

  condition:
    any of them
}