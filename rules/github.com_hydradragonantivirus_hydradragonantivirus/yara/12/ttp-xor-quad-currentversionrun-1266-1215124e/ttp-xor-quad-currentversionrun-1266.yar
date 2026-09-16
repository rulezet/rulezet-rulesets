rule TTP_XOR_QUAD_CurrentVersionRun_1266 {
  strings:
    $key_1266 = { 41 09 [2] 65 07 [2] 4e 2b [2] 60 09 [2] 74 12 [2] 7b 08 [2] 65 15 [2] 67 14 [2] 7c 12 [2] 60 15 [2] 7c 3a }

  condition:
    any of them
}