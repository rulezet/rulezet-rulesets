rule TTP_XOR_QUAD_CurrentVersionRun_f997 {
  strings:
    $key_f997 = { aa f8 [2] 8e f6 [2] a5 da [2] 8b f8 [2] 9f e3 [2] 90 f9 [2] 8e e4 [2] 8c e5 [2] 97 e3 [2] 8b e4 [2] 97 cb }

  condition:
    any of them
}