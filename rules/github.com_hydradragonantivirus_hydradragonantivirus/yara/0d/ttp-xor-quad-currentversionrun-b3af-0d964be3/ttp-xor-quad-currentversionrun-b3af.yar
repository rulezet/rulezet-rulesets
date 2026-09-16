rule TTP_XOR_QUAD_CurrentVersionRun_b3af {
  strings:
    $key_b3af = { e0 c0 [2] c4 ce [2] ef e2 [2] c1 c0 [2] d5 db [2] da c1 [2] c4 dc [2] c6 dd [2] dd db [2] c1 dc [2] dd f3 }

  condition:
    any of them
}