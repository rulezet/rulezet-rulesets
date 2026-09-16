rule TTP_XOR_QUAD_CurrentVersionRun_9d9b {
  strings:
    $key_9d9b = { ce f4 [2] ea fa [2] c1 d6 [2] ef f4 [2] fb ef [2] f4 f5 [2] ea e8 [2] e8 e9 [2] f3 ef [2] ef e8 [2] f3 c7 }

  condition:
    any of them
}