rule TTP_XOR_QUAD_CurrentVersionRun_9dea {
  strings:
    $key_9dea = { ce 85 [2] ea 8b [2] c1 a7 [2] ef 85 [2] fb 9e [2] f4 84 [2] ea 99 [2] e8 98 [2] f3 9e [2] ef 99 [2] f3 b6 }

  condition:
    any of them
}