rule TTP_XOR_QUAD_CurrentVersionRun_7d77 {
  strings:
    $key_7d77 = { 2e 18 [2] 0a 16 [2] 21 3a [2] 0f 18 [2] 1b 03 [2] 14 19 [2] 0a 04 [2] 08 05 [2] 13 03 [2] 0f 04 [2] 13 2b }

  condition:
    any of them
}