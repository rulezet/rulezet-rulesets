rule TTP_XOR_QUAD_CurrentVersionRun_0dc4 {
  strings:
    $key_0dc4 = { 5e ab [2] 7a a5 [2] 51 89 [2] 7f ab [2] 6b b0 [2] 64 aa [2] 7a b7 [2] 78 b6 [2] 63 b0 [2] 7f b7 [2] 63 98 }

  condition:
    any of them
}