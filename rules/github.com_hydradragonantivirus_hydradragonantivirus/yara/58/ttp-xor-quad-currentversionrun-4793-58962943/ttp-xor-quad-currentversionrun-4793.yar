rule TTP_XOR_QUAD_CurrentVersionRun_4793 {
  strings:
    $key_4793 = { 14 fc [2] 30 f2 [2] 1b de [2] 35 fc [2] 21 e7 [2] 2e fd [2] 30 e0 [2] 32 e1 [2] 29 e7 [2] 35 e0 [2] 29 cf }

  condition:
    any of them
}