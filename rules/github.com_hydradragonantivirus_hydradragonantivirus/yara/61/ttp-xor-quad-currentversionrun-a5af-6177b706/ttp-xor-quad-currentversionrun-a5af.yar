rule TTP_XOR_QUAD_CurrentVersionRun_a5af {
  strings:
    $key_a5af = { f6 c0 [2] d2 ce [2] f9 e2 [2] d7 c0 [2] c3 db [2] cc c1 [2] d2 dc [2] d0 dd [2] cb db [2] d7 dc [2] cb f3 }

  condition:
    any of them
}