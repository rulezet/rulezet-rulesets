rule TTP_XOR_QUAD_CurrentVersionRun_9d6c {
  strings:
    $key_9d6c = { ce 03 [2] ea 0d [2] c1 21 [2] ef 03 [2] fb 18 [2] f4 02 [2] ea 1f [2] e8 1e [2] f3 18 [2] ef 1f [2] f3 30 }

  condition:
    any of them
}