rule TTP_XOR_QUAD_CurrentVersionRun_bf97 {
  strings:
    $key_bf97 = { ec f8 [2] c8 f6 [2] e3 da [2] cd f8 [2] d9 e3 [2] d6 f9 [2] c8 e4 [2] ca e5 [2] d1 e3 [2] cd e4 [2] d1 cb }

  condition:
    any of them
}