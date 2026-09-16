rule TTP_XOR_QUAD_CurrentVersionRun_5878 {
  strings:
    $key_5878 = { 0b 17 [2] 2f 19 [2] 04 35 [2] 2a 17 [2] 3e 0c [2] 31 16 [2] 2f 0b [2] 2d 0a [2] 36 0c [2] 2a 0b [2] 36 24 }

  condition:
    any of them
}