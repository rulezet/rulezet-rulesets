rule TTP_XOR_QUAD_CurrentVersionRun_f6d8 {
  strings:
    $key_f6d8 = { a5 b7 [2] 81 b9 [2] aa 95 [2] 84 b7 [2] 90 ac [2] 9f b6 [2] 81 ab [2] 83 aa [2] 98 ac [2] 84 ab [2] 98 84 }

  condition:
    any of them
}