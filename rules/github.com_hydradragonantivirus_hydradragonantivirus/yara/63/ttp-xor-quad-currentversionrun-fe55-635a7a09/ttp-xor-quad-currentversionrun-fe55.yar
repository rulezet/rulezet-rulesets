rule TTP_XOR_QUAD_CurrentVersionRun_fe55 {
  strings:
    $key_fe55 = { ad 3a [2] 89 34 [2] a2 18 [2] 8c 3a [2] 98 21 [2] 97 3b [2] 89 26 [2] 8b 27 [2] 90 21 [2] 8c 26 [2] 90 09 }

  condition:
    any of them
}