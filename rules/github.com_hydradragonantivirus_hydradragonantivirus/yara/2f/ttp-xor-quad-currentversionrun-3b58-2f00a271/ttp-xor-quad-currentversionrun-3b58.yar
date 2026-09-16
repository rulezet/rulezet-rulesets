rule TTP_XOR_QUAD_CurrentVersionRun_3b58 {
  strings:
    $key_3b58 = { 68 37 [2] 4c 39 [2] 67 15 [2] 49 37 [2] 5d 2c [2] 52 36 [2] 4c 2b [2] 4e 2a [2] 55 2c [2] 49 2b [2] 55 04 }

  condition:
    any of them
}