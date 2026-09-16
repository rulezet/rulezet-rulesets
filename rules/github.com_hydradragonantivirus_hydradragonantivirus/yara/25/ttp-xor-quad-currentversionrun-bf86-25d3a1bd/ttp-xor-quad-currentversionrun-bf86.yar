rule TTP_XOR_QUAD_CurrentVersionRun_bf86 {
  strings:
    $key_bf86 = { ec e9 [2] c8 e7 [2] e3 cb [2] cd e9 [2] d9 f2 [2] d6 e8 [2] c8 f5 [2] ca f4 [2] d1 f2 [2] cd f5 [2] d1 da }

  condition:
    any of them
}