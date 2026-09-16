rule TTP_XOR_QUAD_CurrentVersionRun_1546 {
  strings:
    $key_1546 = { 46 29 [2] 62 27 [2] 49 0b [2] 67 29 [2] 73 32 [2] 7c 28 [2] 62 35 [2] 60 34 [2] 7b 32 [2] 67 35 [2] 7b 1a }

  condition:
    any of them
}