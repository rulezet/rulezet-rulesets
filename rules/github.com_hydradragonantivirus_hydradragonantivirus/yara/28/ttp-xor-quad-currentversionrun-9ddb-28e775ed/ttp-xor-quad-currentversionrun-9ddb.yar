rule TTP_XOR_QUAD_CurrentVersionRun_9ddb {
  strings:
    $key_9ddb = { ce b4 [2] ea ba [2] c1 96 [2] ef b4 [2] fb af [2] f4 b5 [2] ea a8 [2] e8 a9 [2] f3 af [2] ef a8 [2] f3 87 }

  condition:
    any of them
}