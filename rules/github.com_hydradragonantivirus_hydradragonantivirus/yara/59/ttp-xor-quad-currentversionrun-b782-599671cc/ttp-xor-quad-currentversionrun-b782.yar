rule TTP_XOR_QUAD_CurrentVersionRun_b782 {
  strings:
    $key_b782 = { e4 ed [2] c0 e3 [2] eb cf [2] c5 ed [2] d1 f6 [2] de ec [2] c0 f1 [2] c2 f0 [2] d9 f6 [2] c5 f1 [2] d9 de }

  condition:
    any of them
}