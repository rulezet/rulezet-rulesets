rule TTP_XOR_QUAD_CurrentVersionRun_9d32 {
  strings:
    $key_9d32 = { ce 5d [2] ea 53 [2] c1 7f [2] ef 5d [2] fb 46 [2] f4 5c [2] ea 41 [2] e8 40 [2] f3 46 [2] ef 41 [2] f3 6e }

  condition:
    any of them
}