rule TTP_XOR_QUAD_CurrentVersionRun_5904 {
  strings:
    $key_5904 = { 0a 6b [2] 2e 65 [2] 05 49 [2] 2b 6b [2] 3f 70 [2] 30 6a [2] 2e 77 [2] 2c 76 [2] 37 70 [2] 2b 77 [2] 37 58 }

  condition:
    any of them
}