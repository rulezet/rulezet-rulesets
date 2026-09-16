rule TTP_XOR_QUAD_CurrentVersionRun_24c4 {
  strings:
    $key_24c4 = { 77 ab [2] 53 a5 [2] 78 89 [2] 56 ab [2] 42 b0 [2] 4d aa [2] 53 b7 [2] 51 b6 [2] 4a b0 [2] 56 b7 [2] 4a 98 }

  condition:
    any of them
}