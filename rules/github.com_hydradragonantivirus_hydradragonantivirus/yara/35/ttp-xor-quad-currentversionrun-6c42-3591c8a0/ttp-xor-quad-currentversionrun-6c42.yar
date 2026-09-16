rule TTP_XOR_QUAD_CurrentVersionRun_6c42 {
  strings:
    $key_6c42 = { 3f 2d [2] 1b 23 [2] 30 0f [2] 1e 2d [2] 0a 36 [2] 05 2c [2] 1b 31 [2] 19 30 [2] 02 36 [2] 1e 31 [2] 02 1e }

  condition:
    any of them
}