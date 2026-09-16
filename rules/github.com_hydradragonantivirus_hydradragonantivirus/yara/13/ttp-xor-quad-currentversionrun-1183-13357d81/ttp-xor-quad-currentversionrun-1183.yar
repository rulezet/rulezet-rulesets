rule TTP_XOR_QUAD_CurrentVersionRun_1183 {
  strings:
    $key_1183 = { 42 ec [2] 66 e2 [2] 4d ce [2] 63 ec [2] 77 f7 [2] 78 ed [2] 66 f0 [2] 64 f1 [2] 7f f7 [2] 63 f0 [2] 7f df }

  condition:
    any of them
}