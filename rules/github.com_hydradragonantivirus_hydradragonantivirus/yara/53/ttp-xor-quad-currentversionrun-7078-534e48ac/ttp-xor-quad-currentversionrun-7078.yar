rule TTP_XOR_QUAD_CurrentVersionRun_7078 {
  strings:
    $key_7078 = { 23 17 [2] 07 19 [2] 2c 35 [2] 02 17 [2] 16 0c [2] 19 16 [2] 07 0b [2] 05 0a [2] 1e 0c [2] 02 0b [2] 1e 24 }

  condition:
    any of them
}