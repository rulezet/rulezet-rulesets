rule TTP_XOR_QUAD_CurrentVersionRun_2b46 {
  strings:
    $key_2b46 = { 78 29 [2] 5c 27 [2] 77 0b [2] 59 29 [2] 4d 32 [2] 42 28 [2] 5c 35 [2] 5e 34 [2] 45 32 [2] 59 35 [2] 45 1a }

  condition:
    any of them
}