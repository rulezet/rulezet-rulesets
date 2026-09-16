rule TTP_XOR_QUAD_CurrentVersionRun_0974 {
  strings:
    $key_0974 = { 5a 1b [2] 7e 15 [2] 55 39 [2] 7b 1b [2] 6f 00 [2] 60 1a [2] 7e 07 [2] 7c 06 [2] 67 00 [2] 7b 07 [2] 67 28 }

  condition:
    any of them
}