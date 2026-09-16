rule TTP_XOR_QUAD_CurrentVersionRun_b593 {
  strings:
    $key_b593 = { e6 fc [2] c2 f2 [2] e9 de [2] c7 fc [2] d3 e7 [2] dc fd [2] c2 e0 [2] c0 e1 [2] db e7 [2] c7 e0 [2] db cf }

  condition:
    any of them
}