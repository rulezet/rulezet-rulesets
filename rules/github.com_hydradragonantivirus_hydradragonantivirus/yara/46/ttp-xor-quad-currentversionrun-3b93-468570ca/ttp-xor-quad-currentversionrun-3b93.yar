rule TTP_XOR_QUAD_CurrentVersionRun_3b93 {
  strings:
    $key_3b93 = { 68 fc [2] 4c f2 [2] 67 de [2] 49 fc [2] 5d e7 [2] 52 fd [2] 4c e0 [2] 4e e1 [2] 55 e7 [2] 49 e0 [2] 55 cf }

  condition:
    any of them
}