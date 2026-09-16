rule TTP_XOR_QUAD_CurrentVersionRun_68af {
  strings:
    $key_68af = { 3b c0 [2] 1f ce [2] 34 e2 [2] 1a c0 [2] 0e db [2] 01 c1 [2] 1f dc [2] 1d dd [2] 06 db [2] 1a dc [2] 06 f3 }

  condition:
    any of them
}