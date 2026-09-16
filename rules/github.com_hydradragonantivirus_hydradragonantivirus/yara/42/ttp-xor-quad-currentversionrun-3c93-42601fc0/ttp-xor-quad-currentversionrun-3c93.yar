rule TTP_XOR_QUAD_CurrentVersionRun_3c93 {
  strings:
    $key_3c93 = { 6f fc [2] 4b f2 [2] 60 de [2] 4e fc [2] 5a e7 [2] 55 fd [2] 4b e0 [2] 49 e1 [2] 52 e7 [2] 4e e0 [2] 52 cf }

  condition:
    any of them
}