rule TTP_XOR_QUAD_CurrentVersionRun_3542 {
  strings:
    $key_3542 = { 66 2d [2] 42 23 [2] 69 0f [2] 47 2d [2] 53 36 [2] 5c 2c [2] 42 31 [2] 40 30 [2] 5b 36 [2] 47 31 [2] 5b 1e }

  condition:
    any of them
}