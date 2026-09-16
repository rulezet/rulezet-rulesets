rule TTP_XOR_QUAD_CurrentVersionRun_9d31 {
  strings:
    $key_9d31 = { ce 5e [2] ea 50 [2] c1 7c [2] ef 5e [2] fb 45 [2] f4 5f [2] ea 42 [2] e8 43 [2] f3 45 [2] ef 42 [2] f3 6d }

  condition:
    any of them
}