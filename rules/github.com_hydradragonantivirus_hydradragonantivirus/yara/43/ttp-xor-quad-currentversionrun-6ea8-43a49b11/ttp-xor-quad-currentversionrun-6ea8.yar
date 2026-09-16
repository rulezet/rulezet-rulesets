rule TTP_XOR_QUAD_CurrentVersionRun_6ea8 {
  strings:
    $key_6ea8 = { 3d c7 [2] 19 c9 [2] 32 e5 [2] 1c c7 [2] 08 dc [2] 07 c6 [2] 19 db [2] 1b da [2] 00 dc [2] 1c db [2] 00 f4 }

  condition:
    any of them
}