rule TTP_XOR_QUAD_CurrentVersionRun_41af {
  strings:
    $key_41af = { 12 c0 [2] 36 ce [2] 1d e2 [2] 33 c0 [2] 27 db [2] 28 c1 [2] 36 dc [2] 34 dd [2] 2f db [2] 33 dc [2] 2f f3 }

  condition:
    any of them
}