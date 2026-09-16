rule TTP_XOR_QUAD_CurrentVersionRun_4e64 {
  strings:
    $key_4e64 = { 1d 0b [2] 39 05 [2] 12 29 [2] 3c 0b [2] 28 10 [2] 27 0a [2] 39 17 [2] 3b 16 [2] 20 10 [2] 3c 17 [2] 20 38 }

  condition:
    any of them
}