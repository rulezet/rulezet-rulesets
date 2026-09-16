rule TTP_XOR_QUAD_CurrentVersionRun_23af {
  strings:
    $key_23af = { 70 c0 [2] 54 ce [2] 7f e2 [2] 51 c0 [2] 45 db [2] 4a c1 [2] 54 dc [2] 56 dd [2] 4d db [2] 51 dc [2] 4d f3 }

  condition:
    any of them
}