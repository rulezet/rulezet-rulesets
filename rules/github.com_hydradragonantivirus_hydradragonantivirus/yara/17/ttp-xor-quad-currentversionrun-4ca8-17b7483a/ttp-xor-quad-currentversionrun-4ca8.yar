rule TTP_XOR_QUAD_CurrentVersionRun_4ca8 {
  strings:
    $key_4ca8 = { 1f c7 [2] 3b c9 [2] 10 e5 [2] 3e c7 [2] 2a dc [2] 25 c6 [2] 3b db [2] 39 da [2] 22 dc [2] 3e db [2] 22 f4 }

  condition:
    any of them
}