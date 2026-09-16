rule TTP_XOR_QUAD_CurrentVersionRun_6c93 {
  strings:
    $key_6c93 = { 3f fc [2] 1b f2 [2] 30 de [2] 1e fc [2] 0a e7 [2] 05 fd [2] 1b e0 [2] 19 e1 [2] 02 e7 [2] 1e e0 [2] 02 cf }

  condition:
    any of them
}