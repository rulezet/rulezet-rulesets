rule TTP_XOR_QUAD_CurrentVersionRun_9d4a {
  strings:
    $key_9d4a = { ce 25 [2] ea 2b [2] c1 07 [2] ef 25 [2] fb 3e [2] f4 24 [2] ea 39 [2] e8 38 [2] f3 3e [2] ef 39 [2] f3 16 }

  condition:
    any of them
}