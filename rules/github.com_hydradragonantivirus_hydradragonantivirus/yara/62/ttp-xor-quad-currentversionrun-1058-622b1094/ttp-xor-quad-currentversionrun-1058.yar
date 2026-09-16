rule TTP_XOR_QUAD_CurrentVersionRun_1058 {
  strings:
    $key_1058 = { 43 37 [2] 67 39 [2] 4c 15 [2] 62 37 [2] 76 2c [2] 79 36 [2] 67 2b [2] 65 2a [2] 7e 2c [2] 62 2b [2] 7e 04 }

  condition:
    any of them
}