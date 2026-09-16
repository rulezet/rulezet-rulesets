rule TTP_XOR_QUAD_CurrentVersionRun_b193 {
  strings:
    $key_b193 = { e2 fc [2] c6 f2 [2] ed de [2] c3 fc [2] d7 e7 [2] d8 fd [2] c6 e0 [2] c4 e1 [2] df e7 [2] c3 e0 [2] df cf }

  condition:
    any of them
}