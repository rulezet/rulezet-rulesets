rule TTP_XOR_QUAD_CurrentVersionRun_9d27 {
  strings:
    $key_9d27 = { ce 48 [2] ea 46 [2] c1 6a [2] ef 48 [2] fb 53 [2] f4 49 [2] ea 54 [2] e8 55 [2] f3 53 [2] ef 54 [2] f3 7b }

  condition:
    any of them
}