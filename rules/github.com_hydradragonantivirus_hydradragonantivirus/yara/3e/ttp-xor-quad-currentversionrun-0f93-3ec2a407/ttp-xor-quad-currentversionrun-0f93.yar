rule TTP_XOR_QUAD_CurrentVersionRun_0f93 {
  strings:
    $key_0f93 = { 5c fc [2] 78 f2 [2] 53 de [2] 7d fc [2] 69 e7 [2] 66 fd [2] 78 e0 [2] 7a e1 [2] 61 e7 [2] 7d e0 [2] 61 cf }

  condition:
    any of them
}