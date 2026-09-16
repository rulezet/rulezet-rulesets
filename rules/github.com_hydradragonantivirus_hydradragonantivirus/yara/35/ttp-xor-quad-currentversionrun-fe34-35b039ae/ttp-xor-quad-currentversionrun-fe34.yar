rule TTP_XOR_QUAD_CurrentVersionRun_fe34 {
  strings:
    $key_fe34 = { ad 5b [2] 89 55 [2] a2 79 [2] 8c 5b [2] 98 40 [2] 97 5a [2] 89 47 [2] 8b 46 [2] 90 40 [2] 8c 47 [2] 90 68 }

  condition:
    any of them
}