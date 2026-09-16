rule TTP_XOR_QUAD_CurrentVersionRun_6f93 {
  strings:
    $key_6f93 = { 3c fc [2] 18 f2 [2] 33 de [2] 1d fc [2] 09 e7 [2] 06 fd [2] 18 e0 [2] 1a e1 [2] 01 e7 [2] 1d e0 [2] 01 cf }

  condition:
    any of them
}