rule TTP_XOR_QUAD_CurrentVersionRun_fe39 {
  strings:
    $key_fe39 = { ad 56 [2] 89 58 [2] a2 74 [2] 8c 56 [2] 98 4d [2] 97 57 [2] 89 4a [2] 8b 4b [2] 90 4d [2] 8c 4a [2] 90 65 }

  condition:
    any of them
}