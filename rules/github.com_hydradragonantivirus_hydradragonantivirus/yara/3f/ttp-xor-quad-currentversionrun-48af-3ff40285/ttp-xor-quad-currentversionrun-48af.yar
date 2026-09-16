rule TTP_XOR_QUAD_CurrentVersionRun_48af {
  strings:
    $key_48af = { 1b c0 [2] 3f ce [2] 14 e2 [2] 3a c0 [2] 2e db [2] 21 c1 [2] 3f dc [2] 3d dd [2] 26 db [2] 3a dc [2] 26 f3 }

  condition:
    any of them
}