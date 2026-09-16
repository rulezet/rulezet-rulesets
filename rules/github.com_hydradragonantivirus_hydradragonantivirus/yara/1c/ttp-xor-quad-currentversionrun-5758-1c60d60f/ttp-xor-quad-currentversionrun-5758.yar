rule TTP_XOR_QUAD_CurrentVersionRun_5758 {
  strings:
    $key_5758 = { 04 37 [2] 20 39 [2] 0b 15 [2] 25 37 [2] 31 2c [2] 3e 36 [2] 20 2b [2] 22 2a [2] 39 2c [2] 25 2b [2] 39 04 }

  condition:
    any of them
}