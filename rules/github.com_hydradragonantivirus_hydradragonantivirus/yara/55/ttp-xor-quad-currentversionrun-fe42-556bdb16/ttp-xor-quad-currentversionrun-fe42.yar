rule TTP_XOR_QUAD_CurrentVersionRun_fe42 {
  strings:
    $key_fe42 = { ad 2d [2] 89 23 [2] a2 0f [2] 8c 2d [2] 98 36 [2] 97 2c [2] 89 31 [2] 8b 30 [2] 90 36 [2] 8c 31 [2] 90 1e }

  condition:
    any of them
}