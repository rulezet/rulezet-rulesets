rule TTP_XOR_QUAD_CurrentVersionRun_2e06 {
  strings:
    $key_2e06 = { 7d 69 [2] 59 67 [2] 72 4b [2] 5c 69 [2] 48 72 [2] 47 68 [2] 59 75 [2] 5b 74 [2] 40 72 [2] 5c 75 [2] 40 5a }

  condition:
    any of them
}