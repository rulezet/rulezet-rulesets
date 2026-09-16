rule TTP_XOR_QUAD_CurrentVersionRun_4cb5 {
  strings:
    $key_4cb5 = { 1f da [2] 3b d4 [2] 10 f8 [2] 3e da [2] 2a c1 [2] 25 db [2] 3b c6 [2] 39 c7 [2] 22 c1 [2] 3e c6 [2] 22 e9 }

  condition:
    any of them
}