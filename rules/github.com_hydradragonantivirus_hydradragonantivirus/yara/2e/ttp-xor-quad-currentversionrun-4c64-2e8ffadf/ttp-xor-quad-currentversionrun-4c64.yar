rule TTP_XOR_QUAD_CurrentVersionRun_4c64 {
  strings:
    $key_4c64 = { 1f 0b [2] 3b 05 [2] 10 29 [2] 3e 0b [2] 2a 10 [2] 25 0a [2] 3b 17 [2] 39 16 [2] 22 10 [2] 3e 17 [2] 22 38 }

  condition:
    any of them
}