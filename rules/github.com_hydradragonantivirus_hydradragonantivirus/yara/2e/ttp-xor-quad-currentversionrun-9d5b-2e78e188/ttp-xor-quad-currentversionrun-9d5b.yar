rule TTP_XOR_QUAD_CurrentVersionRun_9d5b {
  strings:
    $key_9d5b = { ce 34 [2] ea 3a [2] c1 16 [2] ef 34 [2] fb 2f [2] f4 35 [2] ea 28 [2] e8 29 [2] f3 2f [2] ef 28 [2] f3 07 }

  condition:
    any of them
}