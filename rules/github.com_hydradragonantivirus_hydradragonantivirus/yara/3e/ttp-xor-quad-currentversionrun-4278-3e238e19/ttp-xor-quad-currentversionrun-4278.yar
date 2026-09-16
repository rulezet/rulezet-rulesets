rule TTP_XOR_QUAD_CurrentVersionRun_4278 {
  strings:
    $key_4278 = { 11 17 [2] 35 19 [2] 1e 35 [2] 30 17 [2] 24 0c [2] 2b 16 [2] 35 0b [2] 37 0a [2] 2c 0c [2] 30 0b [2] 2c 24 }

  condition:
    any of them
}