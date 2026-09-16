rule TTP_XOR_QUAD_CurrentVersionRun_1042 {
  strings:
    $key_1042 = { 43 2d [2] 67 23 [2] 4c 0f [2] 62 2d [2] 76 36 [2] 79 2c [2] 67 31 [2] 65 30 [2] 7e 36 [2] 62 31 [2] 7e 1e }

  condition:
    any of them
}