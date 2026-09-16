rule TTP_XOR_QUAD_CurrentVersionRun_6b74 {
  strings:
    $key_6b74 = { 38 1b [2] 1c 15 [2] 37 39 [2] 19 1b [2] 0d 00 [2] 02 1a [2] 1c 07 [2] 1e 06 [2] 05 00 [2] 19 07 [2] 05 28 }

  condition:
    any of them
}