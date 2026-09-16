rule TTP_XOR_QUAD_CurrentVersionRun_4958 {
  strings:
    $key_4958 = { 1a 37 [2] 3e 39 [2] 15 15 [2] 3b 37 [2] 2f 2c [2] 20 36 [2] 3e 2b [2] 3c 2a [2] 27 2c [2] 3b 2b [2] 27 04 }

  condition:
    any of them
}