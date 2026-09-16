rule TTP_XOR_QUAD_CurrentVersionRun_fe78 {
  strings:
    $key_fe78 = { ad 17 [2] 89 19 [2] a2 35 [2] 8c 17 [2] 98 0c [2] 97 16 [2] 89 0b [2] 8b 0a [2] 90 0c [2] 8c 0b [2] 90 24 }

  condition:
    any of them
}