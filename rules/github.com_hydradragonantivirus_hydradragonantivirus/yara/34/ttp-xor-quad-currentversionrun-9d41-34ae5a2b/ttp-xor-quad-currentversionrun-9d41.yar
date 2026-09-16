rule TTP_XOR_QUAD_CurrentVersionRun_9d41 {
  strings:
    $key_9d41 = { ce 2e [2] ea 20 [2] c1 0c [2] ef 2e [2] fb 35 [2] f4 2f [2] ea 32 [2] e8 33 [2] f3 35 [2] ef 32 [2] f3 1d }

  condition:
    any of them
}