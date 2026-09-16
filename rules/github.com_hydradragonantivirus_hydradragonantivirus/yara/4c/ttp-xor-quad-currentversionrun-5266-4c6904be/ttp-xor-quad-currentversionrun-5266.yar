rule TTP_XOR_QUAD_CurrentVersionRun_5266 {
  strings:
    $key_5266 = { 01 09 [2] 25 07 [2] 0e 2b [2] 20 09 [2] 34 12 [2] 3b 08 [2] 25 15 [2] 27 14 [2] 3c 12 [2] 20 15 [2] 3c 3a }

  condition:
    any of them
}