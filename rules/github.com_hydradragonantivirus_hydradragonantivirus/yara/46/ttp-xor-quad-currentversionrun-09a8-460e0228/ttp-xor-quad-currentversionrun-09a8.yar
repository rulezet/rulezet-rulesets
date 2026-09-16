rule TTP_XOR_QUAD_CurrentVersionRun_09a8 {
  strings:
    $key_09a8 = { 5a c7 [2] 7e c9 [2] 55 e5 [2] 7b c7 [2] 6f dc [2] 60 c6 [2] 7e db [2] 7c da [2] 67 dc [2] 7b db [2] 67 f4 }

  condition:
    any of them
}