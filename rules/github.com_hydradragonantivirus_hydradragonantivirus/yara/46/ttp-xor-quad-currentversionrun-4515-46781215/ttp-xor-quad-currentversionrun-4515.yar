rule TTP_XOR_QUAD_CurrentVersionRun_4515 {
  strings:
    $key_4515 = { 16 7a [2] 32 74 [2] 19 58 [2] 37 7a [2] 23 61 [2] 2c 7b [2] 32 66 [2] 30 67 [2] 2b 61 [2] 37 66 [2] 2b 49 }

  condition:
    any of them
}