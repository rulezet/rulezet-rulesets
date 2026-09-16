rule TTP_XOR_QUAD_CurrentVersionRun_5978 {
  strings:
    $key_5978 = { 0a 17 [2] 2e 19 [2] 05 35 [2] 2b 17 [2] 3f 0c [2] 30 16 [2] 2e 0b [2] 2c 0a [2] 37 0c [2] 2b 0b [2] 37 24 }

  condition:
    any of them
}