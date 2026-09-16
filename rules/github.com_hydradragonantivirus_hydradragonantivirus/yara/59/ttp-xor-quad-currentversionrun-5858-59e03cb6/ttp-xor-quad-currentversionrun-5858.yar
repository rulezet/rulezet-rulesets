rule TTP_XOR_QUAD_CurrentVersionRun_5858 {
  strings:
    $key_5858 = { 0b 37 [2] 2f 39 [2] 04 15 [2] 2a 37 [2] 3e 2c [2] 31 36 [2] 2f 2b [2] 2d 2a [2] 36 2c [2] 2a 2b [2] 36 04 }

  condition:
    any of them
}