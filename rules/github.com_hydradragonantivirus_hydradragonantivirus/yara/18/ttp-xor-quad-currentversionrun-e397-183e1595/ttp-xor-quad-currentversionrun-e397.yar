rule TTP_XOR_QUAD_CurrentVersionRun_e397 {
  strings:
    $key_e397 = { b0 f8 [2] 94 f6 [2] bf da [2] 91 f8 [2] 85 e3 [2] 8a f9 [2] 94 e4 [2] 96 e5 [2] 8d e3 [2] 91 e4 [2] 8d cb }

  condition:
    any of them
}