rule TTP_XOR_QUAD_CurrentVersionRun_3936 {
  strings:
    $key_3936 = { 6a 59 [2] 4e 57 [2] 65 7b [2] 4b 59 [2] 5f 42 [2] 50 58 [2] 4e 45 [2] 4c 44 [2] 57 42 [2] 4b 45 [2] 57 6a }

  condition:
    any of them
}