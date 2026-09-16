rule TTP_XOR_QUAD_CurrentVersionRun_bf84 {
  strings:
    $key_bf84 = { ec eb [2] c8 e5 [2] e3 c9 [2] cd eb [2] d9 f0 [2] d6 ea [2] c8 f7 [2] ca f6 [2] d1 f0 [2] cd f7 [2] d1 d8 }

  condition:
    any of them
}