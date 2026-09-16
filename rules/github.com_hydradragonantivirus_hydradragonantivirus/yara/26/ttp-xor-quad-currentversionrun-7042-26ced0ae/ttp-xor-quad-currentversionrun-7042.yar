rule TTP_XOR_QUAD_CurrentVersionRun_7042 {
  strings:
    $key_7042 = { 23 2d [2] 07 23 [2] 2c 0f [2] 02 2d [2] 16 36 [2] 19 2c [2] 07 31 [2] 05 30 [2] 1e 36 [2] 02 31 [2] 1e 1e }

  condition:
    any of them
}