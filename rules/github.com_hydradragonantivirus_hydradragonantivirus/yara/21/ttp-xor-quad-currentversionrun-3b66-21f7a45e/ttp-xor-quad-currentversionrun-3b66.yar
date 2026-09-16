rule TTP_XOR_QUAD_CurrentVersionRun_3b66 {
  strings:
    $key_3b66 = { 68 09 [2] 4c 07 [2] 67 2b [2] 49 09 [2] 5d 12 [2] 52 08 [2] 4c 15 [2] 4e 14 [2] 55 12 [2] 49 15 [2] 55 3a }

  condition:
    any of them
}