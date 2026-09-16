rule TTP_XOR_QUAD_CurrentVersionRun_fe47 {
  strings:
    $key_fe47 = { ad 28 [2] 89 26 [2] a2 0a [2] 8c 28 [2] 98 33 [2] 97 29 [2] 89 34 [2] 8b 35 [2] 90 33 [2] 8c 34 [2] 90 1b }

  condition:
    any of them
}