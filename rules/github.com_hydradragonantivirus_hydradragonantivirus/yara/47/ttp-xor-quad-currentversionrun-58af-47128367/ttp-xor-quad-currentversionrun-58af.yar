rule TTP_XOR_QUAD_CurrentVersionRun_58af {
  strings:
    $key_58af = { 0b c0 [2] 2f ce [2] 04 e2 [2] 2a c0 [2] 3e db [2] 31 c1 [2] 2f dc [2] 2d dd [2] 36 db [2] 2a dc [2] 36 f3 }

  condition:
    any of them
}