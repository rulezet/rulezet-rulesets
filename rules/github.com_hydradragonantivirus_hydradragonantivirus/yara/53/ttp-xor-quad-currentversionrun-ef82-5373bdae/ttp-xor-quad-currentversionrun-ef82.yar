rule TTP_XOR_QUAD_CurrentVersionRun_ef82 {
  strings:
    $key_ef82 = { bc ed [2] 98 e3 [2] b3 cf [2] 9d ed [2] 89 f6 [2] 86 ec [2] 98 f1 [2] 9a f0 [2] 81 f6 [2] 9d f1 [2] 81 de }

  condition:
    any of them
}