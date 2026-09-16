rule TTP_XOR_QUAD_CurrentVersionRun_7f09 {
  strings:
    $key_7f09 = { 2c 66 [2] 08 68 [2] 23 44 [2] 0d 66 [2] 19 7d [2] 16 67 [2] 08 7a [2] 0a 7b [2] 11 7d [2] 0d 7a [2] 11 55 }

  condition:
    any of them
}