rule TTP_XOR_QUAD_CurrentVersionRun_9d1c {
  strings:
    $key_9d1c = { ce 73 [2] ea 7d [2] c1 51 [2] ef 73 [2] fb 68 [2] f4 72 [2] ea 6f [2] e8 6e [2] f3 68 [2] ef 6f [2] f3 40 }

  condition:
    any of them
}