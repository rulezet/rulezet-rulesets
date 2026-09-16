rule TTP_XOR_QUAD_CurrentVersionRun_6d42 {
  strings:
    $key_6d42 = { 3e 2d [2] 1a 23 [2] 31 0f [2] 1f 2d [2] 0b 36 [2] 04 2c [2] 1a 31 [2] 18 30 [2] 03 36 [2] 1f 31 [2] 03 1e }

  condition:
    any of them
}