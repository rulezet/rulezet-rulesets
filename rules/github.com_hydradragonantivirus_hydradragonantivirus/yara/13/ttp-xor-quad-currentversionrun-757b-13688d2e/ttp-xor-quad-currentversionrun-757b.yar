rule TTP_XOR_QUAD_CurrentVersionRun_757b {
  strings:
    $key_757b = { 26 14 [2] 02 1a [2] 29 36 [2] 07 14 [2] 13 0f [2] 1c 15 [2] 02 08 [2] 00 09 [2] 1b 0f [2] 07 08 [2] 1b 27 }

  condition:
    any of them
}