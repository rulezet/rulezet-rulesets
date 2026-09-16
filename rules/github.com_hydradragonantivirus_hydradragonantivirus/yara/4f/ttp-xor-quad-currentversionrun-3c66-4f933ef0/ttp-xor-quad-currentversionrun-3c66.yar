rule TTP_XOR_QUAD_CurrentVersionRun_3c66 {
  strings:
    $key_3c66 = { 6f 09 [2] 4b 07 [2] 60 2b [2] 4e 09 [2] 5a 12 [2] 55 08 [2] 4b 15 [2] 49 14 [2] 52 12 [2] 4e 15 [2] 52 3a }

  condition:
    any of them
}