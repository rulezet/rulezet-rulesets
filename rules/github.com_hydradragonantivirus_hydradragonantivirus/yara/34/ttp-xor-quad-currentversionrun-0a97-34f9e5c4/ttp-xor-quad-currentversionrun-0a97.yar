rule TTP_XOR_QUAD_CurrentVersionRun_0a97 {
  strings:
    $key_0a97 = { 59 f8 [2] 7d f6 [2] 56 da [2] 78 f8 [2] 6c e3 [2] 63 f9 [2] 7d e4 [2] 7f e5 [2] 64 e3 [2] 78 e4 [2] 64 cb }

  condition:
    any of them
}