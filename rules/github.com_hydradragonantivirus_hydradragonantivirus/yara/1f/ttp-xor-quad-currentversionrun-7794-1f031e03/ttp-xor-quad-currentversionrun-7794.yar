rule TTP_XOR_QUAD_CurrentVersionRun_7794 {
  strings:
    $key_7794 = { 24 fb [2] 00 f5 [2] 2b d9 [2] 05 fb [2] 11 e0 [2] 1e fa [2] 00 e7 [2] 02 e6 [2] 19 e0 [2] 05 e7 [2] 19 c8 }

  condition:
    any of them
}