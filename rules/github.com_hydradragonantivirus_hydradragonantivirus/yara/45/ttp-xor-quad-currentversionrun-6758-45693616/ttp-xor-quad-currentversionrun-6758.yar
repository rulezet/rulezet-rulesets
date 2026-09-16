rule TTP_XOR_QUAD_CurrentVersionRun_6758 {
  strings:
    $key_6758 = { 34 37 [2] 10 39 [2] 3b 15 [2] 15 37 [2] 01 2c [2] 0e 36 [2] 10 2b [2] 12 2a [2] 09 2c [2] 15 2b [2] 09 04 }

  condition:
    any of them
}