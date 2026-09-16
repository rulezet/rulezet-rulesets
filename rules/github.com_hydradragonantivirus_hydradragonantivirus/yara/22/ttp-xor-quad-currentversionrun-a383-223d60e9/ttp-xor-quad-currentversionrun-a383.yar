rule TTP_XOR_QUAD_CurrentVersionRun_a383 {
  strings:
    $key_a383 = { f0 ec [2] d4 e2 [2] ff ce [2] d1 ec [2] c5 f7 [2] ca ed [2] d4 f0 [2] d6 f1 [2] cd f7 [2] d1 f0 [2] cd df }

  condition:
    any of them
}