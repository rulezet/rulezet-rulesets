rule TTP_XOR_QUAD_CurrentVersionRun_4077 {
  strings:
    $key_4077 = { 13 18 [2] 37 16 [2] 1c 3a [2] 32 18 [2] 26 03 [2] 29 19 [2] 37 04 [2] 35 05 [2] 2e 03 [2] 32 04 [2] 2e 2b }

  condition:
    any of them
}