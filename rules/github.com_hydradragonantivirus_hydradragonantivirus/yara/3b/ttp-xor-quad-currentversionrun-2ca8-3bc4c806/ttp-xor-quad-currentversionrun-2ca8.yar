rule TTP_XOR_QUAD_CurrentVersionRun_2ca8 {
  strings:
    $key_2ca8 = { 7f c7 [2] 5b c9 [2] 70 e5 [2] 5e c7 [2] 4a dc [2] 45 c6 [2] 5b db [2] 59 da [2] 42 dc [2] 5e db [2] 42 f4 }

  condition:
    any of them
}