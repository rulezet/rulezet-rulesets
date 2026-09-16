rule TTP_XOR_QUAD_CurrentVersionRun_9de3 {
  strings:
    $key_9de3 = { ce 8c [2] ea 82 [2] c1 ae [2] ef 8c [2] fb 97 [2] f4 8d [2] ea 90 [2] e8 91 [2] f3 97 [2] ef 90 [2] f3 bf }

  condition:
    any of them
}