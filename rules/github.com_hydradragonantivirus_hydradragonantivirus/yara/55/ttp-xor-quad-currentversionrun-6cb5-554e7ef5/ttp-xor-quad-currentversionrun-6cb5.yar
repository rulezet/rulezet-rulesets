rule TTP_XOR_QUAD_CurrentVersionRun_6cb5 {
  strings:
    $key_6cb5 = { 3f da [2] 1b d4 [2] 30 f8 [2] 1e da [2] 0a c1 [2] 05 db [2] 1b c6 [2] 19 c7 [2] 02 c1 [2] 1e c6 [2] 02 e9 }

  condition:
    any of them
}