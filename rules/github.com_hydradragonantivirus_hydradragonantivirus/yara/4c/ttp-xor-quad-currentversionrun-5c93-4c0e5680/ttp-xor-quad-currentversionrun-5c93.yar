rule TTP_XOR_QUAD_CurrentVersionRun_5c93 {
  strings:
    $key_5c93 = { 0f fc [2] 2b f2 [2] 00 de [2] 2e fc [2] 3a e7 [2] 35 fd [2] 2b e0 [2] 29 e1 [2] 32 e7 [2] 2e e0 [2] 32 cf }

  condition:
    any of them
}