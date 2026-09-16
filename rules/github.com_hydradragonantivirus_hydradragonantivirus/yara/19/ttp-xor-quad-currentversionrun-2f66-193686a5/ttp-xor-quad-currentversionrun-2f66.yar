rule TTP_XOR_QUAD_CurrentVersionRun_2f66 {
  strings:
    $key_2f66 = { 7c 09 [2] 58 07 [2] 73 2b [2] 5d 09 [2] 49 12 [2] 46 08 [2] 58 15 [2] 5a 14 [2] 41 12 [2] 5d 15 [2] 41 3a }

  condition:
    any of them
}