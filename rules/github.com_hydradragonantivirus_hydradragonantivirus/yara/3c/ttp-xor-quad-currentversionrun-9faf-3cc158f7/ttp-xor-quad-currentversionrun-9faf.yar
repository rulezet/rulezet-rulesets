rule TTP_XOR_QUAD_CurrentVersionRun_9faf {
  strings:
    $key_9faf = { cc c0 [2] e8 ce [2] c3 e2 [2] ed c0 [2] f9 db [2] f6 c1 [2] e8 dc [2] ea dd [2] f1 db [2] ed dc [2] f1 f3 }

  condition:
    any of them
}