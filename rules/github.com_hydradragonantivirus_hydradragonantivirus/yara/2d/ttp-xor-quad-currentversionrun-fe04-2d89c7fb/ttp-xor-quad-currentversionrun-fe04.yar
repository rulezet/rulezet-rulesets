rule TTP_XOR_QUAD_CurrentVersionRun_fe04 {
  strings:
    $key_fe04 = { ad 6b [2] 89 65 [2] a2 49 [2] 8c 6b [2] 98 70 [2] 97 6a [2] 89 77 [2] 8b 76 [2] 90 70 [2] 8c 77 [2] 90 58 }

  condition:
    any of them
}