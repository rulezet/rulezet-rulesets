rule TTP_XOR_QUAD_CurrentVersionRun_fe58 {
  strings:
    $key_fe58 = { ad 37 [2] 89 39 [2] a2 15 [2] 8c 37 [2] 98 2c [2] 97 36 [2] 89 2b [2] 8b 2a [2] 90 2c [2] 8c 2b [2] 90 04 }

  condition:
    any of them
}