rule TTP_XOR_QUAD_CurrentVersionRun_f8af {
  strings:
    $key_f8af = { ab c0 [2] 8f ce [2] a4 e2 [2] 8a c0 [2] 9e db [2] 91 c1 [2] 8f dc [2] 8d dd [2] 96 db [2] 8a dc [2] 96 f3 }

  condition:
    any of them
}