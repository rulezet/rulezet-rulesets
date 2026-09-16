rule TTP_XOR_QUAD_CurrentVersionRun_7577 {
  strings:
    $key_7577 = { 26 18 [2] 02 16 [2] 29 3a [2] 07 18 [2] 13 03 [2] 1c 19 [2] 02 04 [2] 00 05 [2] 1b 03 [2] 07 04 [2] 1b 2b }

  condition:
    any of them
}