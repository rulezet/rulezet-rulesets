rule TTP_XOR_QUAD_CurrentVersionRun_e1af {
  strings:
    $key_e1af = { b2 c0 [2] 96 ce [2] bd e2 [2] 93 c0 [2] 87 db [2] 88 c1 [2] 96 dc [2] 94 dd [2] 8f db [2] 93 dc [2] 8f f3 }

  condition:
    any of them
}