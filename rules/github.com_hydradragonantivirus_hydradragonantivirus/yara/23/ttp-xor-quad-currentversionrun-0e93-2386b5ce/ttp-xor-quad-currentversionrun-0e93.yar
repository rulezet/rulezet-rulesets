rule TTP_XOR_QUAD_CurrentVersionRun_0e93 {
  strings:
    $key_0e93 = { 5d fc [2] 79 f2 [2] 52 de [2] 7c fc [2] 68 e7 [2] 67 fd [2] 79 e0 [2] 7b e1 [2] 60 e7 [2] 7c e0 [2] 60 cf }

  condition:
    any of them
}