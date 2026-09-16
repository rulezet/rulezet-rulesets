rule TTP_XOR_QUAD_CurrentVersionRun_b993 {
  strings:
    $key_b993 = { ea fc [2] ce f2 [2] e5 de [2] cb fc [2] df e7 [2] d0 fd [2] ce e0 [2] cc e1 [2] d7 e7 [2] cb e0 [2] d7 cf }

  condition:
    any of them
}