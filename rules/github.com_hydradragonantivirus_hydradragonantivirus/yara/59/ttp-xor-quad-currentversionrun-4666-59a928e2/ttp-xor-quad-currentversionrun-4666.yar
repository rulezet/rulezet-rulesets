rule TTP_XOR_QUAD_CurrentVersionRun_4666 {
  strings:
    $key_4666 = { 15 09 [2] 31 07 [2] 1a 2b [2] 34 09 [2] 20 12 [2] 2f 08 [2] 31 15 [2] 33 14 [2] 28 12 [2] 34 15 [2] 28 3a }

  condition:
    any of them
}