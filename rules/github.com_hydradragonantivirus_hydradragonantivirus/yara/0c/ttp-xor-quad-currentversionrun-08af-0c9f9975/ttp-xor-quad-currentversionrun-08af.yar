rule TTP_XOR_QUAD_CurrentVersionRun_08af {
  strings:
    $key_08af = { 5b c0 [2] 7f ce [2] 54 e2 [2] 7a c0 [2] 6e db [2] 61 c1 [2] 7f dc [2] 7d dd [2] 66 db [2] 7a dc [2] 66 f3 }

  condition:
    any of them
}