rule TTP_XOR_QUAD_CurrentVersionRun_2026 {
  strings:
    $key_2026 = { 73 49 [2] 57 47 [2] 7c 6b [2] 52 49 [2] 46 52 [2] 49 48 [2] 57 55 [2] 55 54 [2] 4e 52 [2] 52 55 [2] 4e 7a }

  condition:
    any of them
}