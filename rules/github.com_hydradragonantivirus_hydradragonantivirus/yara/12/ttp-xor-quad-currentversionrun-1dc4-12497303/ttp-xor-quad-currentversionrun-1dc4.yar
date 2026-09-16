rule TTP_XOR_QUAD_CurrentVersionRun_1dc4 {
  strings:
    $key_1dc4 = { 4e ab [2] 6a a5 [2] 41 89 [2] 6f ab [2] 7b b0 [2] 74 aa [2] 6a b7 [2] 68 b6 [2] 73 b0 [2] 6f b7 [2] 73 98 }

  condition:
    any of them
}