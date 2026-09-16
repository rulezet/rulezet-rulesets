rule TTP_XOR_QUAD_CurrentVersionRun_bf93 {
  strings:
    $key_bf93 = { ec fc [2] c8 f2 [2] e3 de [2] cd fc [2] d9 e7 [2] d6 fd [2] c8 e0 [2] ca e1 [2] d1 e7 [2] cd e0 [2] d1 cf }

  condition:
    any of them
}