rule TTP_XOR_QUAD_CurrentVersionRun_fe29 {
  strings:
    $key_fe29 = { ad 46 [2] 89 48 [2] a2 64 [2] 8c 46 [2] 98 5d [2] 97 47 [2] 89 5a [2] 8b 5b [2] 90 5d [2] 8c 5a [2] 90 75 }

  condition:
    any of them
}