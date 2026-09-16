rule TTP_XOR_QUAD_CurrentVersionRun_9d51 {
  strings:
    $key_9d51 = { ce 3e [2] ea 30 [2] c1 1c [2] ef 3e [2] fb 25 [2] f4 3f [2] ea 22 [2] e8 23 [2] f3 25 [2] ef 22 [2] f3 0d }

  condition:
    any of them
}