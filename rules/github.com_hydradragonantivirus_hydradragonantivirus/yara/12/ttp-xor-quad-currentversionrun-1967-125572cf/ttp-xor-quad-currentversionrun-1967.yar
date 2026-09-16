rule TTP_XOR_QUAD_CurrentVersionRun_1967 {
  strings:
    $key_1967 = { 4a 08 [2] 6e 06 [2] 45 2a [2] 6b 08 [2] 7f 13 [2] 70 09 [2] 6e 14 [2] 6c 15 [2] 77 13 [2] 6b 14 [2] 77 3b }

  condition:
    any of them
}