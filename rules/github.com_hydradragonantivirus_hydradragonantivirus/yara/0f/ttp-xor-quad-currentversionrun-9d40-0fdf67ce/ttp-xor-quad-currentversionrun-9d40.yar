rule TTP_XOR_QUAD_CurrentVersionRun_9d40 {
  strings:
    $key_9d40 = { ce 2f [2] ea 21 [2] c1 0d [2] ef 2f [2] fb 34 [2] f4 2e [2] ea 33 [2] e8 32 [2] f3 34 [2] ef 33 [2] f3 1c }

  condition:
    any of them
}