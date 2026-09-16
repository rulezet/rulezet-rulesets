rule TTP_XOR_QUAD_CurrentVersionRun_1b66 {
  strings:
    $key_1b66 = { 48 09 [2] 6c 07 [2] 47 2b [2] 69 09 [2] 7d 12 [2] 72 08 [2] 6c 15 [2] 6e 14 [2] 75 12 [2] 69 15 [2] 75 3a }

  condition:
    any of them
}