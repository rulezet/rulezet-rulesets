rule TTP_XOR_QUAD_CurrentVersionRun_0a36 {
  strings:
    $key_0a36 = { 59 59 [2] 7d 57 [2] 56 7b [2] 78 59 [2] 6c 42 [2] 63 58 [2] 7d 45 [2] 7f 44 [2] 64 42 [2] 78 45 [2] 64 6a }

  condition:
    any of them
}