rule TTP_XOR_QUAD_CurrentVersionRun_0858 {
  strings:
    $key_0858 = { 5b 37 [2] 7f 39 [2] 54 15 [2] 7a 37 [2] 6e 2c [2] 61 36 [2] 7f 2b [2] 7d 2a [2] 66 2c [2] 7a 2b [2] 66 04 }

  condition:
    any of them
}