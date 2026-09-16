rule TTP_XOR_QUAD_CurrentVersionRun_eea8 {
  strings:
    $key_eea8 = { bd c7 [2] 99 c9 [2] b2 e5 [2] 9c c7 [2] 88 dc [2] 87 c6 [2] 99 db [2] 9b da [2] 80 dc [2] 9c db [2] 80 f4 }

  condition:
    any of them
}