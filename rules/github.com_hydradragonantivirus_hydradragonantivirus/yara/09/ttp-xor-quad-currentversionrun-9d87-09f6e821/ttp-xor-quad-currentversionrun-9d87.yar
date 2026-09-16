rule TTP_XOR_QUAD_CurrentVersionRun_9d87 {
  strings:
    $key_9d87 = { ce e8 [2] ea e6 [2] c1 ca [2] ef e8 [2] fb f3 [2] f4 e9 [2] ea f4 [2] e8 f5 [2] f3 f3 [2] ef f4 [2] f3 db }

  condition:
    any of them
}