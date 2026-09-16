rule TTP_XOR_QUAD_CurrentVersionRun_3166 {
  strings:
    $key_3166 = { 62 09 [2] 46 07 [2] 6d 2b [2] 43 09 [2] 57 12 [2] 58 08 [2] 46 15 [2] 44 14 [2] 5f 12 [2] 43 15 [2] 5f 3a }

  condition:
    any of them
}