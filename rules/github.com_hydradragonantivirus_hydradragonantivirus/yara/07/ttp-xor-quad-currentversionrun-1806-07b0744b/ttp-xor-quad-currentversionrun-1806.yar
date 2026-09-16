rule TTP_XOR_QUAD_CurrentVersionRun_1806 {
  strings:
    $key_1806 = { 4b 69 [2] 6f 67 [2] 44 4b [2] 6a 69 [2] 7e 72 [2] 71 68 [2] 6f 75 [2] 6d 74 [2] 76 72 [2] 6a 75 [2] 76 5a }

  condition:
    any of them
}