rule TTP_XOR_QUAD_CurrentVersionRun_3586 {
  strings:
    $key_3586 = { 66 e9 [2] 42 e7 [2] 69 cb [2] 47 e9 [2] 53 f2 [2] 5c e8 [2] 42 f5 [2] 40 f4 [2] 5b f2 [2] 47 f5 [2] 5b da }

  condition:
    any of them
}