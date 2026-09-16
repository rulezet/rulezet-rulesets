rule TTP_XOR_QUAD_CurrentVersionRun_4382 {
  strings:
    $key_4382 = { 10 ed [2] 34 e3 [2] 1f cf [2] 31 ed [2] 25 f6 [2] 2a ec [2] 34 f1 [2] 36 f0 [2] 2d f6 [2] 31 f1 [2] 2d de }

  condition:
    any of them
}