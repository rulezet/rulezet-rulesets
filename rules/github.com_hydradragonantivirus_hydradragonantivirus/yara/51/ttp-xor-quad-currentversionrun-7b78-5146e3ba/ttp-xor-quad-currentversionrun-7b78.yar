rule TTP_XOR_QUAD_CurrentVersionRun_7b78 {
  strings:
    $key_7b78 = { 28 17 [2] 0c 19 [2] 27 35 [2] 09 17 [2] 1d 0c [2] 12 16 [2] 0c 0b [2] 0e 0a [2] 15 0c [2] 09 0b [2] 15 24 }

  condition:
    any of them
}