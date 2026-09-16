rule TTP_XOR_QUAD_CurrentVersionRun_2507 {
  strings:
    $key_2507 = { 76 68 [2] 52 66 [2] 79 4a [2] 57 68 [2] 43 73 [2] 4c 69 [2] 52 74 [2] 50 75 [2] 4b 73 [2] 57 74 [2] 4b 5b }

  condition:
    any of them
}