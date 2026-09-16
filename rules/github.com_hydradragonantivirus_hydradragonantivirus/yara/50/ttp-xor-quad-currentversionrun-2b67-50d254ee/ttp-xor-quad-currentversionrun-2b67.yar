rule TTP_XOR_QUAD_CurrentVersionRun_2b67 {
  strings:
    $key_2b67 = { 78 08 [2] 5c 06 [2] 77 2a [2] 59 08 [2] 4d 13 [2] 42 09 [2] 5c 14 [2] 5e 15 [2] 45 13 [2] 59 14 [2] 45 3b }

  condition:
    any of them
}