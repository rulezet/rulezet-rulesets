rule TTP_XOR_QUAD_CurrentVersionRun_2266 {
  strings:
    $key_2266 = { 71 09 [2] 55 07 [2] 7e 2b [2] 50 09 [2] 44 12 [2] 4b 08 [2] 55 15 [2] 57 14 [2] 4c 12 [2] 50 15 [2] 4c 3a }

  condition:
    any of them
}