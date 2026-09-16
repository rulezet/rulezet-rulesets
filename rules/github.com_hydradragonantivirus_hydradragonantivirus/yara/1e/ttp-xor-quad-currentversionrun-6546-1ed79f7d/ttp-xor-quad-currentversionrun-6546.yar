rule TTP_XOR_QUAD_CurrentVersionRun_6546 {
  strings:
    $key_6546 = { 36 29 [2] 12 27 [2] 39 0b [2] 17 29 [2] 03 32 [2] 0c 28 [2] 12 35 [2] 10 34 [2] 0b 32 [2] 17 35 [2] 0b 1a }

  condition:
    any of them
}