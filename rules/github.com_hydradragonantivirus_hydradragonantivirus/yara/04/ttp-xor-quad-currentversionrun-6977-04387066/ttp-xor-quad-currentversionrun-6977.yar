rule TTP_XOR_QUAD_CurrentVersionRun_6977 {
  strings:
    $key_6977 = { 3a 18 [2] 1e 16 [2] 35 3a [2] 1b 18 [2] 0f 03 [2] 00 19 [2] 1e 04 [2] 1c 05 [2] 07 03 [2] 1b 04 [2] 07 2b }

  condition:
    any of them
}