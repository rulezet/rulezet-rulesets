rule TTP_XOR_QUAD_CurrentVersionRun_7c93 {
  strings:
    $key_7c93 = { 2f fc [2] 0b f2 [2] 20 de [2] 0e fc [2] 1a e7 [2] 15 fd [2] 0b e0 [2] 09 e1 [2] 12 e7 [2] 0e e0 [2] 12 cf }

  condition:
    any of them
}