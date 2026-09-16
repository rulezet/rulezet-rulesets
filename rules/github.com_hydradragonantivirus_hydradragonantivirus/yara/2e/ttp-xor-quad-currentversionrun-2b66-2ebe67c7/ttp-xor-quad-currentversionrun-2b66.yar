rule TTP_XOR_QUAD_CurrentVersionRun_2b66 {
  strings:
    $key_2b66 = { 78 09 [2] 5c 07 [2] 77 2b [2] 59 09 [2] 4d 12 [2] 42 08 [2] 5c 15 [2] 5e 14 [2] 45 12 [2] 59 15 [2] 45 3a }

  condition:
    any of them
}