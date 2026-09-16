rule TTP_XOR_QUAD_CurrentVersionRun_9d22 {
  strings:
    $key_9d22 = { ce 4d [2] ea 43 [2] c1 6f [2] ef 4d [2] fb 56 [2] f4 4c [2] ea 51 [2] e8 50 [2] f3 56 [2] ef 51 [2] f3 7e }

  condition:
    any of them
}