rule TTP_XOR_QUAD_CurrentVersionRun_78af {
  strings:
    $key_78af = { 2b c0 [2] 0f ce [2] 24 e2 [2] 0a c0 [2] 1e db [2] 11 c1 [2] 0f dc [2] 0d dd [2] 16 db [2] 0a dc [2] 16 f3 }

  condition:
    any of them
}