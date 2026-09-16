rule TTP_XOR_QUAD_CurrentVersionRun_2da8 {
  strings:
    $key_2da8 = { 7e c7 [2] 5a c9 [2] 71 e5 [2] 5f c7 [2] 4b dc [2] 44 c6 [2] 5a db [2] 58 da [2] 43 dc [2] 5f db [2] 43 f4 }

  condition:
    any of them
}