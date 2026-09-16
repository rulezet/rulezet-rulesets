rule TTP_XOR_QUAD_CurrentVersionRun_ff82 {
  strings:
    $key_ff82 = { ac ed [2] 88 e3 [2] a3 cf [2] 8d ed [2] 99 f6 [2] 96 ec [2] 88 f1 [2] 8a f0 [2] 91 f6 [2] 8d f1 [2] 91 de }

  condition:
    any of them
}