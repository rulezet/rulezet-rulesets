rule TTP_XOR_QUAD_CurrentVersionRun_2206 {
  strings:
    $key_2206 = { 71 69 [2] 55 67 [2] 7e 4b [2] 50 69 [2] 44 72 [2] 4b 68 [2] 55 75 [2] 57 74 [2] 4c 72 [2] 50 75 [2] 4c 5a }

  condition:
    any of them
}