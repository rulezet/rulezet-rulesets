rule TTP_XOR_QUAD_CurrentVersionRun_3966 {
  strings:
    $key_3966 = { 6a 09 [2] 4e 07 [2] 65 2b [2] 4b 09 [2] 5f 12 [2] 50 08 [2] 4e 15 [2] 4c 14 [2] 57 12 [2] 4b 15 [2] 57 3a }

  condition:
    any of them
}