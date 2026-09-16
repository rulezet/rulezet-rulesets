rule TTP_XOR_QUAD_CurrentVersionRun_fe64 {
  strings:
    $key_fe64 = { ad 0b [2] 89 05 [2] a2 29 [2] 8c 0b [2] 98 10 [2] 97 0a [2] 89 17 [2] 8b 16 [2] 90 10 [2] 8c 17 [2] 90 38 }

  condition:
    any of them
}