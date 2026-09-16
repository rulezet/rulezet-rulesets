rule TTP_XOR_QUAD_CurrentVersionRun_4da8 {
  strings:
    $key_4da8 = { 1e c7 [2] 3a c9 [2] 11 e5 [2] 3f c7 [2] 2b dc [2] 24 c6 [2] 3a db [2] 38 da [2] 23 dc [2] 3f db [2] 23 f4 }

  condition:
    any of them
}