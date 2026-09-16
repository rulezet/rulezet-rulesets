rule TTP_XOR_QUAD_CurrentVersionRun_5193 {
  strings:
    $key_5193 = { 02 fc [2] 26 f2 [2] 0d de [2] 23 fc [2] 37 e7 [2] 38 fd [2] 26 e0 [2] 24 e1 [2] 3f e7 [2] 23 e0 [2] 3f cf }

  condition:
    any of them
}