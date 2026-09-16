rule TTP_XOR_QUAD_CurrentVersionRun_6006 {
  strings:
    $key_6006 = { 33 69 [2] 17 67 [2] 3c 4b [2] 12 69 [2] 06 72 [2] 09 68 [2] 17 75 [2] 15 74 [2] 0e 72 [2] 12 75 [2] 0e 5a }

  condition:
    any of them
}