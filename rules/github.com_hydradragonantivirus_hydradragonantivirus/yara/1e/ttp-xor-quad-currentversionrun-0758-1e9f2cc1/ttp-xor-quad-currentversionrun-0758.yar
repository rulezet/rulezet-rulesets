rule TTP_XOR_QUAD_CurrentVersionRun_0758 {
  strings:
    $key_0758 = { 54 37 [2] 70 39 [2] 5b 15 [2] 75 37 [2] 61 2c [2] 6e 36 [2] 70 2b [2] 72 2a [2] 69 2c [2] 75 2b [2] 69 04 }

  condition:
    any of them
}