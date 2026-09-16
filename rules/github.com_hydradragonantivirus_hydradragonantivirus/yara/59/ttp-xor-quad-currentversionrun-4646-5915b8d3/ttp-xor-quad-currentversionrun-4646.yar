rule TTP_XOR_QUAD_CurrentVersionRun_4646 {
  strings:
    $key_4646 = { 15 29 [2] 31 27 [2] 1a 0b [2] 34 29 [2] 20 32 [2] 2f 28 [2] 31 35 [2] 33 34 [2] 28 32 [2] 34 35 [2] 28 1a }

  condition:
    any of them
}