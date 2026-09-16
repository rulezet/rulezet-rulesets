rule TTP_XOR_QUAD_CurrentVersionRun_1d36 {
  strings:
    $key_1d36 = { 4e 59 [2] 6a 57 [2] 41 7b [2] 6f 59 [2] 7b 42 [2] 74 58 [2] 6a 45 [2] 68 44 [2] 73 42 [2] 6f 45 [2] 73 6a }

  condition:
    any of them
}