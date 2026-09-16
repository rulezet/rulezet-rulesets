rule TTP_XOR_QUAD_CurrentVersionRun_0893 {
  strings:
    $key_0893 = { 5b fc [2] 7f f2 [2] 54 de [2] 7a fc [2] 6e e7 [2] 61 fd [2] 7f e0 [2] 7d e1 [2] 66 e7 [2] 7a e0 [2] 66 cf }

  condition:
    any of them
}