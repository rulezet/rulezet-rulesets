rule TTP_XOR_QUAD_CurrentVersionRun_7277 {
  strings:
    $key_7277 = { 21 18 [2] 05 16 [2] 2e 3a [2] 00 18 [2] 14 03 [2] 1b 19 [2] 05 04 [2] 07 05 [2] 1c 03 [2] 00 04 [2] 1c 2b }

  condition:
    any of them
}