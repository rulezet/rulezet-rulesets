rule TTP_XOR_QUAD_CurrentVersionRun_2b74 {
  strings:
    $key_2b74 = { 78 1b [2] 5c 15 [2] 77 39 [2] 59 1b [2] 4d 00 [2] 42 1a [2] 5c 07 [2] 5e 06 [2] 45 00 [2] 59 07 [2] 45 28 }

  condition:
    any of them
}