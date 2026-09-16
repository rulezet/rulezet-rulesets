rule TTP_XOR_QUAD_CurrentVersionRun_f6e4 {
  strings:
    $key_f6e4 = { a5 8b [2] 81 85 [2] aa a9 [2] 84 8b [2] 90 90 [2] 9f 8a [2] 81 97 [2] 83 96 [2] 98 90 [2] 84 97 [2] 98 b8 }

  condition:
    any of them
}