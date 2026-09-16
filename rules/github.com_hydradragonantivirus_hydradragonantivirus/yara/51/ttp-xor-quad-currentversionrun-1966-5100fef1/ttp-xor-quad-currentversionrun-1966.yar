rule TTP_XOR_QUAD_CurrentVersionRun_1966 {
  strings:
    $key_1966 = { 4a 09 [2] 6e 07 [2] 45 2b [2] 6b 09 [2] 7f 12 [2] 70 08 [2] 6e 15 [2] 6c 14 [2] 77 12 [2] 6b 15 [2] 77 3a }

  condition:
    any of them
}