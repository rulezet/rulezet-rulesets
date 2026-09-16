rule TTP_XOR_QUAD_CurrentVersionRun_7d42 {
  strings:
    $key_7d42 = { 2e 2d [2] 0a 23 [2] 21 0f [2] 0f 2d [2] 1b 36 [2] 14 2c [2] 0a 31 [2] 08 30 [2] 13 36 [2] 0f 31 [2] 13 1e }

  condition:
    any of them
}