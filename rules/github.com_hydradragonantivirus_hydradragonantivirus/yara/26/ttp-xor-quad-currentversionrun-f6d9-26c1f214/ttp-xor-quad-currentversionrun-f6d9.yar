rule TTP_XOR_QUAD_CurrentVersionRun_f6d9 {
  strings:
    $key_f6d9 = { a5 b6 [2] 81 b8 [2] aa 94 [2] 84 b6 [2] 90 ad [2] 9f b7 [2] 81 aa [2] 83 ab [2] 98 ad [2] 84 aa [2] 98 85 }

  condition:
    any of them
}