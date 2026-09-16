rule TTP_XOR_QUAD_CurrentVersionRun_6d66 {
  strings:
    $key_6d66 = { 3e 09 [2] 1a 07 [2] 31 2b [2] 1f 09 [2] 0b 12 [2] 04 08 [2] 1a 15 [2] 18 14 [2] 03 12 [2] 1f 15 [2] 03 3a }

  condition:
    any of them
}