rule TTP_XOR_QUAD_CurrentVersionRun_9df2 {
  strings:
    $key_9df2 = { ce 9d [2] ea 93 [2] c1 bf [2] ef 9d [2] fb 86 [2] f4 9c [2] ea 81 [2] e8 80 [2] f3 86 [2] ef 81 [2] f3 ae }

  condition:
    any of them
}