rule TTP_XOR_QUAD_CurrentVersionRun_4036 {
  strings:
    $key_4036 = { 13 59 [2] 37 57 [2] 1c 7b [2] 32 59 [2] 26 42 [2] 29 58 [2] 37 45 [2] 35 44 [2] 2e 42 [2] 32 45 [2] 2e 6a }

  condition:
    any of them
}