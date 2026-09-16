rule TTP_XOR_QUAD_CurrentVersionRun_0793 {
  strings:
    $key_0793 = { 54 fc [2] 70 f2 [2] 5b de [2] 75 fc [2] 61 e7 [2] 6e fd [2] 70 e0 [2] 72 e1 [2] 69 e7 [2] 75 e0 [2] 69 cf }

  condition:
    any of them
}