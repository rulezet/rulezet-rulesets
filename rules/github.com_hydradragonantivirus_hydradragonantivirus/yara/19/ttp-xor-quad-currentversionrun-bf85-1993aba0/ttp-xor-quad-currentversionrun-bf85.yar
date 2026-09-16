rule TTP_XOR_QUAD_CurrentVersionRun_bf85 {
  strings:
    $key_bf85 = { ec ea [2] c8 e4 [2] e3 c8 [2] cd ea [2] d9 f1 [2] d6 eb [2] c8 f6 [2] ca f7 [2] d1 f1 [2] cd f6 [2] d1 d9 }

  condition:
    any of them
}