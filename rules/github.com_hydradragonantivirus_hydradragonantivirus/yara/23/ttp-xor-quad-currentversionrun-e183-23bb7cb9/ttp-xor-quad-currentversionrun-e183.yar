rule TTP_XOR_QUAD_CurrentVersionRun_e183 {
  strings:
    $key_e183 = { b2 ec [2] 96 e2 [2] bd ce [2] 93 ec [2] 87 f7 [2] 88 ed [2] 96 f0 [2] 94 f1 [2] 8f f7 [2] 93 f0 [2] 8f df }

  condition:
    any of them
}