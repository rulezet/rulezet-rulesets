rule TTP_XOR_QUAD_CurrentVersionRun_9d72 {
  strings:
    $key_9d72 = { ce 1d [2] ea 13 [2] c1 3f [2] ef 1d [2] fb 06 [2] f4 1c [2] ea 01 [2] e8 00 [2] f3 06 [2] ef 01 [2] f3 2e }

  condition:
    any of them
}