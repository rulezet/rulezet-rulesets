rule TTP_XOR_QUAD_CurrentVersionRun_fb82 {
  strings:
    $key_fb82 = { a8 ed [2] 8c e3 [2] a7 cf [2] 89 ed [2] 9d f6 [2] 92 ec [2] 8c f1 [2] 8e f0 [2] 95 f6 [2] 89 f1 [2] 95 de }

  condition:
    any of them
}