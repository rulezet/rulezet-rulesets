rule TTP_XOR_QUAD_CurrentVersionRun_9dcc {
  strings:
    $key_9dcc = { ce a3 [2] ea ad [2] c1 81 [2] ef a3 [2] fb b8 [2] f4 a2 [2] ea bf [2] e8 be [2] f3 b8 [2] ef bf [2] f3 90 }

  condition:
    any of them
}