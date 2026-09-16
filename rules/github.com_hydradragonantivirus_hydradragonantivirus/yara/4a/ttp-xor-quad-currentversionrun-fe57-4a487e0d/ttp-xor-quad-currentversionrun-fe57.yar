rule TTP_XOR_QUAD_CurrentVersionRun_fe57 {
  strings:
    $key_fe57 = { ad 38 [2] 89 36 [2] a2 1a [2] 8c 38 [2] 98 23 [2] 97 39 [2] 89 24 [2] 8b 25 [2] 90 23 [2] 8c 24 [2] 90 0b }

  condition:
    any of them
}