rule TTP_XOR_QUAD_CurrentVersionRun_7183 {
  strings:
    $key_7183 = { 22 ec [2] 06 e2 [2] 2d ce [2] 03 ec [2] 17 f7 [2] 18 ed [2] 06 f0 [2] 04 f1 [2] 1f f7 [2] 03 f0 [2] 1f df }

  condition:
    any of them
}