rule TTP_XOR_QUAD_CurrentVersionRun_33af {
  strings:
    $key_33af = { 60 c0 [2] 44 ce [2] 6f e2 [2] 41 c0 [2] 55 db [2] 5a c1 [2] 44 dc [2] 46 dd [2] 5d db [2] 41 dc [2] 5d f3 }

  condition:
    any of them
}