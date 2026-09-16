rule TTP_XOR_QUAD_CurrentVersionRun_4183 {
  strings:
    $key_4183 = { 12 ec [2] 36 e2 [2] 1d ce [2] 33 ec [2] 27 f7 [2] 28 ed [2] 36 f0 [2] 34 f1 [2] 2f f7 [2] 33 f0 [2] 2f df }

  condition:
    any of them
}