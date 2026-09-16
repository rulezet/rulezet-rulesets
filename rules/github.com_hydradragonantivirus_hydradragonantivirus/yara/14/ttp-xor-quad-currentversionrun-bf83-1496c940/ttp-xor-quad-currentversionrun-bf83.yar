rule TTP_XOR_QUAD_CurrentVersionRun_bf83 {
  strings:
    $key_bf83 = { ec ec [2] c8 e2 [2] e3 ce [2] cd ec [2] d9 f7 [2] d6 ed [2] c8 f0 [2] ca f1 [2] d1 f7 [2] cd f0 [2] d1 df }

  condition:
    any of them
}