rule TTP_XOR_QUAD_CurrentVersionRun_0586 {
  strings:
    $key_0586 = { 56 e9 [2] 72 e7 [2] 59 cb [2] 77 e9 [2] 63 f2 [2] 6c e8 [2] 72 f5 [2] 70 f4 [2] 6b f2 [2] 77 f5 [2] 6b da }

  condition:
    any of them
}