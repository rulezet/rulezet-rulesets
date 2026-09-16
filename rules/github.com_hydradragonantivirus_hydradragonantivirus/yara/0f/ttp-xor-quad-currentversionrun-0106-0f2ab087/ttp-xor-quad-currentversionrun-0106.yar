rule TTP_XOR_QUAD_CurrentVersionRun_0106 {
  strings:
    $key_0106 = { 52 69 [2] 76 67 [2] 5d 4b [2] 73 69 [2] 67 72 [2] 68 68 [2] 76 75 [2] 74 74 [2] 6f 72 [2] 73 75 [2] 6f 5a }

  condition:
    any of them
}