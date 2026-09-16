rule TTP_XOR_QUAD_CurrentVersionRun_2836 {
  strings:
    $key_2836 = { 7b 59 [2] 5f 57 [2] 74 7b [2] 5a 59 [2] 4e 42 [2] 41 58 [2] 5f 45 [2] 5d 44 [2] 46 42 [2] 5a 45 [2] 46 6a }

  condition:
    any of them
}