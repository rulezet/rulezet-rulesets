rule TTP_XOR_QUAD_CurrentVersionRun_6636 {
  strings:
    $key_6636 = { 35 59 [2] 11 57 [2] 3a 7b [2] 14 59 [2] 00 42 [2] 0f 58 [2] 11 45 [2] 13 44 [2] 08 42 [2] 14 45 [2] 08 6a }

  condition:
    any of them
}