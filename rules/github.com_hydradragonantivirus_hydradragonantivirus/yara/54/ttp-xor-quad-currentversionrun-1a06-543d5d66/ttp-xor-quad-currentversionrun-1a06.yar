rule TTP_XOR_QUAD_CurrentVersionRun_1a06 {
  strings:
    $key_1a06 = { 49 69 [2] 6d 67 [2] 46 4b [2] 68 69 [2] 7c 72 [2] 73 68 [2] 6d 75 [2] 6f 74 [2] 74 72 [2] 68 75 [2] 74 5a }

  condition:
    any of them
}