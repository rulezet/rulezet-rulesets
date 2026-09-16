rule TTP_XOR_QUAD_CurrentVersionRun_fe27 {
  strings:
    $key_fe27 = { ad 48 [2] 89 46 [2] a2 6a [2] 8c 48 [2] 98 53 [2] 97 49 [2] 89 54 [2] 8b 55 [2] 90 53 [2] 8c 54 [2] 90 7b }

  condition:
    any of them
}