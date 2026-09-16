rule TTP_XOR_QUAD_CurrentVersionRun_6793 {
  strings:
    $key_6793 = { 34 fc [2] 10 f2 [2] 3b de [2] 15 fc [2] 01 e7 [2] 0e fd [2] 10 e0 [2] 12 e1 [2] 09 e7 [2] 15 e0 [2] 09 cf }

  condition:
    any of them
}