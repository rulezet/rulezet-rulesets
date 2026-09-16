rule TTP_XOR_QUAD_CurrentVersionRun_9de6 {
  strings:
    $key_9de6 = { ce 89 [2] ea 87 [2] c1 ab [2] ef 89 [2] fb 92 [2] f4 88 [2] ea 95 [2] e8 94 [2] f3 92 [2] ef 95 [2] f3 ba }

  condition:
    any of them
}