rule TTP_XOR_QUAD_CurrentVersionRun_6183 {
  strings:
    $key_6183 = { 32 ec [2] 16 e2 [2] 3d ce [2] 13 ec [2] 07 f7 [2] 08 ed [2] 16 f0 [2] 14 f1 [2] 0f f7 [2] 13 f0 [2] 0f df }

  condition:
    any of them
}