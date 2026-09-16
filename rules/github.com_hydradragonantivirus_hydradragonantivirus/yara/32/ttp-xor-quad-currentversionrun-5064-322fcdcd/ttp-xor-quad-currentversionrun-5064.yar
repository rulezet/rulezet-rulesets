rule TTP_XOR_QUAD_CurrentVersionRun_5064 {
  strings:
    $key_5064 = { 03 0b [2] 27 05 [2] 0c 29 [2] 22 0b [2] 36 10 [2] 39 0a [2] 27 17 [2] 25 16 [2] 3e 10 [2] 22 17 [2] 3e 38 }

  condition:
    any of them
}