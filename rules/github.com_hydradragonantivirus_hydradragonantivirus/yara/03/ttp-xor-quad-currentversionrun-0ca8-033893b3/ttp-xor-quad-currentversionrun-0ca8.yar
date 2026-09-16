rule TTP_XOR_QUAD_CurrentVersionRun_0ca8 {
  strings:
    $key_0ca8 = { 5f c7 [2] 7b c9 [2] 50 e5 [2] 7e c7 [2] 6a dc [2] 65 c6 [2] 7b db [2] 79 da [2] 62 dc [2] 7e db [2] 62 f4 }

  condition:
    any of them
}