rule TTP_XOR_QUAD_CurrentVersionRun_6b42 {
  strings:
    $key_6b42 = { 38 2d [2] 1c 23 [2] 37 0f [2] 19 2d [2] 0d 36 [2] 02 2c [2] 1c 31 [2] 1e 30 [2] 05 36 [2] 19 31 [2] 05 1e }

  condition:
    any of them
}