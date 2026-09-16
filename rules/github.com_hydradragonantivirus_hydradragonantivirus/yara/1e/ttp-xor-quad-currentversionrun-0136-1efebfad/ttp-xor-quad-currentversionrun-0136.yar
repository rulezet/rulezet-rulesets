rule TTP_XOR_QUAD_CurrentVersionRun_0136 {
  strings:
    $key_0136 = { 52 59 [2] 76 57 [2] 5d 7b [2] 73 59 [2] 67 42 [2] 68 58 [2] 76 45 [2] 74 44 [2] 6f 42 [2] 73 45 [2] 6f 6a }

  condition:
    any of them
}