rule TTP_XOR_QUAD_CurrentVersionRun_be82 {
  strings:
    $key_be82 = { ed ed [2] c9 e3 [2] e2 cf [2] cc ed [2] d8 f6 [2] d7 ec [2] c9 f1 [2] cb f0 [2] d0 f6 [2] cc f1 [2] d0 de }

  condition:
    any of them
}