rule TTP_XOR_QUAD_CurrentVersionRun_fb83 {
  strings:
    $key_fb83 = { a8 ec [2] 8c e2 [2] a7 ce [2] 89 ec [2] 9d f7 [2] 92 ed [2] 8c f0 [2] 8e f1 [2] 95 f7 [2] 89 f0 [2] 95 df }

  condition:
    any of them
}