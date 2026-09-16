rule TTP_XOR_QUAD_CurrentVersionRun_5793 {
  strings:
    $key_5793 = { 04 fc [2] 20 f2 [2] 0b de [2] 25 fc [2] 31 e7 [2] 3e fd [2] 20 e0 [2] 22 e1 [2] 39 e7 [2] 25 e0 [2] 39 cf }

  condition:
    any of them
}