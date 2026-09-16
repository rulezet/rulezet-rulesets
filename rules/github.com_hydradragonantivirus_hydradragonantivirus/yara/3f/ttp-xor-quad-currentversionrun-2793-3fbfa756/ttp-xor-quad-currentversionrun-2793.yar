rule TTP_XOR_QUAD_CurrentVersionRun_2793 {
  strings:
    $key_2793 = { 74 fc [2] 50 f2 [2] 7b de [2] 55 fc [2] 41 e7 [2] 4e fd [2] 50 e0 [2] 52 e1 [2] 49 e7 [2] 55 e0 [2] 49 cf }

  condition:
    any of them
}