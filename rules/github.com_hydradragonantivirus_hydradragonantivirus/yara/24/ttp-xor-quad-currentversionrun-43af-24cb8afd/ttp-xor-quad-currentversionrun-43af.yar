rule TTP_XOR_QUAD_CurrentVersionRun_43af {
  strings:
    $key_43af = { 10 c0 [2] 34 ce [2] 1f e2 [2] 31 c0 [2] 25 db [2] 2a c1 [2] 34 dc [2] 36 dd [2] 2d db [2] 31 dc [2] 2d f3 }

  condition:
    any of them
}