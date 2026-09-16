rule TTP_XOR_QUAD_CurrentVersionRun_9dbf {
  strings:
    $key_9dbf = { ce d0 [2] ea de [2] c1 f2 [2] ef d0 [2] fb cb [2] f4 d1 [2] ea cc [2] e8 cd [2] f3 cb [2] ef cc [2] f3 e3 }

  condition:
    any of them
}