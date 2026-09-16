rule TTP_XOR_QUAD_CurrentVersionRun_9daf {
  strings:
    $key_9daf = { ce c0 [2] ea ce [2] c1 e2 [2] ef c0 [2] fb db [2] f4 c1 [2] ea dc [2] e8 dd [2] f3 db [2] ef dc [2] f3 f3 }

  condition:
    any of them
}