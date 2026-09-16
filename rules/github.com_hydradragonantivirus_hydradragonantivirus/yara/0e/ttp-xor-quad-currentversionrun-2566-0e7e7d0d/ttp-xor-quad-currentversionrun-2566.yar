rule TTP_XOR_QUAD_CurrentVersionRun_2566 {
  strings:
    $key_2566 = { 76 09 [2] 52 07 [2] 79 2b [2] 57 09 [2] 43 12 [2] 4c 08 [2] 52 15 [2] 50 14 [2] 4b 12 [2] 57 15 [2] 4b 3a }

  condition:
    any of them
}