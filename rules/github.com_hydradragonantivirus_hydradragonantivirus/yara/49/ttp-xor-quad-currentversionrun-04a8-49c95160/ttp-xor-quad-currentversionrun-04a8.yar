rule TTP_XOR_QUAD_CurrentVersionRun_04a8 {
  strings:
    $key_04a8 = { 57 c7 [2] 73 c9 [2] 58 e5 [2] 76 c7 [2] 62 dc [2] 6d c6 [2] 73 db [2] 71 da [2] 6a dc [2] 76 db [2] 6a f4 }

  condition:
    any of them
}