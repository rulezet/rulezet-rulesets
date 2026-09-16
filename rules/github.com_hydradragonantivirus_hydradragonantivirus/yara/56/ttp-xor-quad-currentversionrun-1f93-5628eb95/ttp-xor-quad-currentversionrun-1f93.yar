rule TTP_XOR_QUAD_CurrentVersionRun_1f93 {
  strings:
    $key_1f93 = { 4c fc [2] 68 f2 [2] 43 de [2] 6d fc [2] 79 e7 [2] 76 fd [2] 68 e0 [2] 6a e1 [2] 71 e7 [2] 6d e0 [2] 71 cf }

  condition:
    any of them
}