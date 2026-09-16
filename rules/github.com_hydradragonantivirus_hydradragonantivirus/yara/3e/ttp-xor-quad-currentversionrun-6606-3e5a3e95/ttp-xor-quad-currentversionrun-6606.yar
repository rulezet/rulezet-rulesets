rule TTP_XOR_QUAD_CurrentVersionRun_6606 {
  strings:
    $key_6606 = { 35 69 [2] 11 67 [2] 3a 4b [2] 14 69 [2] 00 72 [2] 0f 68 [2] 11 75 [2] 13 74 [2] 08 72 [2] 14 75 [2] 08 5a }

  condition:
    any of them
}