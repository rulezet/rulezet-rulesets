rule TTP_XOR_QUAD_CurrentVersionRun_3236 {
  strings:
    $key_3236 = { 61 59 [2] 45 57 [2] 6e 7b [2] 40 59 [2] 54 42 [2] 5b 58 [2] 45 45 [2] 47 44 [2] 5c 42 [2] 40 45 [2] 5c 6a }

  condition:
    any of them
}