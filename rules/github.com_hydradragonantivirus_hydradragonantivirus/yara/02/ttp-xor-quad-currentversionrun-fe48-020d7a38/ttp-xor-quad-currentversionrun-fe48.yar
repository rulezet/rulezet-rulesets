rule TTP_XOR_QUAD_CurrentVersionRun_fe48 {
  strings:
    $key_fe48 = { ad 27 [2] 89 29 [2] a2 05 [2] 8c 27 [2] 98 3c [2] 97 26 [2] 89 3b [2] 8b 3a [2] 90 3c [2] 8c 3b [2] 90 14 }

  condition:
    any of them
}