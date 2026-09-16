rule TTP_XOR_QUAD_CurrentVersionRun_6cb4 {
  strings:
    $key_6cb4 = { 3f db [2] 1b d5 [2] 30 f9 [2] 1e db [2] 0a c0 [2] 05 da [2] 1b c7 [2] 19 c6 [2] 02 c0 [2] 1e c7 [2] 02 e8 }

  condition:
    any of them
}