rule TTP_XOR_QUAD_CurrentVersionRun_9de7 {
  strings:
    $key_9de7 = { ce 88 [2] ea 86 [2] c1 aa [2] ef 88 [2] fb 93 [2] f4 89 [2] ea 94 [2] e8 95 [2] f3 93 [2] ef 94 [2] f3 bb }

  condition:
    any of them
}