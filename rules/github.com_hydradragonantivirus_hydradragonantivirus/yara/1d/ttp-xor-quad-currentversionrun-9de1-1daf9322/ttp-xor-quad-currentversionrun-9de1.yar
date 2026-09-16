rule TTP_XOR_QUAD_CurrentVersionRun_9de1 {
  strings:
    $key_9de1 = { ce 8e [2] ea 80 [2] c1 ac [2] ef 8e [2] fb 95 [2] f4 8f [2] ea 92 [2] e8 93 [2] f3 95 [2] ef 92 [2] f3 bd }

  condition:
    any of them
}