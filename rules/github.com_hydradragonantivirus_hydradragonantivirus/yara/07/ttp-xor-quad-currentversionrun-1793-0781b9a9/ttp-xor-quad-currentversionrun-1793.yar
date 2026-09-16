rule TTP_XOR_QUAD_CurrentVersionRun_1793 {
  strings:
    $key_1793 = { 44 fc [2] 60 f2 [2] 4b de [2] 65 fc [2] 71 e7 [2] 7e fd [2] 60 e0 [2] 62 e1 [2] 79 e7 [2] 65 e0 [2] 79 cf }

  condition:
    any of them
}