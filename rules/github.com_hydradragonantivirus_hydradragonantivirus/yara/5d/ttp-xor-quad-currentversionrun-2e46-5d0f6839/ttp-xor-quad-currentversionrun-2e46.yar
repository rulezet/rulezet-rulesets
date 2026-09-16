rule TTP_XOR_QUAD_CurrentVersionRun_2e46 {
  strings:
    $key_2e46 = { 7d 29 [2] 59 27 [2] 72 0b [2] 5c 29 [2] 48 32 [2] 47 28 [2] 59 35 [2] 5b 34 [2] 40 32 [2] 5c 35 [2] 40 1a }

  condition:
    any of them
}