rule TTP_XOR_QUAD_CurrentVersionRun_5e08 {
  strings:
    $key_5e08 = { 0d 67 [2] 29 69 [2] 02 45 [2] 2c 67 [2] 38 7c [2] 37 66 [2] 29 7b [2] 2b 7a [2] 30 7c [2] 2c 7b [2] 30 54 }

  condition:
    any of them
}