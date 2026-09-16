rule TTP_XOR_QUAD_CurrentVersionRun_6d46 {
  strings:
    $key_6d46 = { 3e 29 [2] 1a 27 [2] 31 0b [2] 1f 29 [2] 0b 32 [2] 04 28 [2] 1a 35 [2] 18 34 [2] 03 32 [2] 1f 35 [2] 03 1a }

  condition:
    any of them
}