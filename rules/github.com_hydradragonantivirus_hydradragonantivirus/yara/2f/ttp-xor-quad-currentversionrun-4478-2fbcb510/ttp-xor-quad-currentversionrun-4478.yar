rule TTP_XOR_QUAD_CurrentVersionRun_4478 {
  strings:
    $key_4478 = { 17 17 [2] 33 19 [2] 18 35 [2] 36 17 [2] 22 0c [2] 2d 16 [2] 33 0b [2] 31 0a [2] 2a 0c [2] 36 0b [2] 2a 24 }

  condition:
    any of them
}