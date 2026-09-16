rule TTP_XOR_QUAD_CurrentVersionRun_3a36 {
  strings:
    $key_3a36 = { 69 59 [2] 4d 57 [2] 66 7b [2] 48 59 [2] 5c 42 [2] 53 58 [2] 4d 45 [2] 4f 44 [2] 54 42 [2] 48 45 [2] 54 6a }

  condition:
    any of them
}