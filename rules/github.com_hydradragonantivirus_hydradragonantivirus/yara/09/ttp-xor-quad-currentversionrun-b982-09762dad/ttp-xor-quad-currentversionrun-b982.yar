rule TTP_XOR_QUAD_CurrentVersionRun_b982 {
  strings:
    $key_b982 = { ea ed [2] ce e3 [2] e5 cf [2] cb ed [2] df f6 [2] d0 ec [2] ce f1 [2] cc f0 [2] d7 f6 [2] cb f1 [2] d7 de }

  condition:
    any of them
}