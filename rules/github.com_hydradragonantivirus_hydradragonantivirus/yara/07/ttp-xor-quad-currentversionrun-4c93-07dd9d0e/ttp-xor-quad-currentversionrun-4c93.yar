rule TTP_XOR_QUAD_CurrentVersionRun_4c93 {
  strings:
    $key_4c93 = { 1f fc [2] 3b f2 [2] 10 de [2] 3e fc [2] 2a e7 [2] 25 fd [2] 3b e0 [2] 39 e1 [2] 22 e7 [2] 3e e0 [2] 22 cf }

  condition:
    any of them
}