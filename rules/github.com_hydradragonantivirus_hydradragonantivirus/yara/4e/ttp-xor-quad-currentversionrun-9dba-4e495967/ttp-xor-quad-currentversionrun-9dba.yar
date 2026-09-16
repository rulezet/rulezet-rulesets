rule TTP_XOR_QUAD_CurrentVersionRun_9dba {
  strings:
    $key_9dba = { ce d5 [2] ea db [2] c1 f7 [2] ef d5 [2] fb ce [2] f4 d4 [2] ea c9 [2] e8 c8 [2] f3 ce [2] ef c9 [2] f3 e6 }

  condition:
    any of them
}