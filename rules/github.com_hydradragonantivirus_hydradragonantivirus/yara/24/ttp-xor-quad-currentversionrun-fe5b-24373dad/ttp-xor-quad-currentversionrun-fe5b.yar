rule TTP_XOR_QUAD_CurrentVersionRun_fe5b {
  strings:
    $key_fe5b = { ad 34 [2] 89 3a [2] a2 16 [2] 8c 34 [2] 98 2f [2] 97 35 [2] 89 28 [2] 8b 29 [2] 90 2f [2] 8c 28 [2] 90 07 }

  condition:
    any of them
}