rule TTP_XOR_QUAD_CurrentVersionRun_9d02 {
  strings:
    $key_9d02 = { ce 6d [2] ea 63 [2] c1 4f [2] ef 6d [2] fb 76 [2] f4 6c [2] ea 71 [2] e8 70 [2] f3 76 [2] ef 71 [2] f3 5e }

  condition:
    any of them
}