rule TTP_XOR_QUAD_CurrentVersionRun_bf82 {
  strings:
    $key_bf82 = { ec ed [2] c8 e3 [2] e3 cf [2] cd ed [2] d9 f6 [2] d6 ec [2] c8 f1 [2] ca f0 [2] d1 f6 [2] cd f1 [2] d1 de }

  condition:
    any of them
}