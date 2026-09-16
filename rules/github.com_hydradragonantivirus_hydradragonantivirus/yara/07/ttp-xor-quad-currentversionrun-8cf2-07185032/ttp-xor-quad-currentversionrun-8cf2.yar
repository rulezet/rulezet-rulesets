rule TTP_XOR_QUAD_CurrentVersionRun_8cf2 {
  strings:
    $key_8cf2 = { df 9d [2] fb 93 [2] d0 bf [2] fe 9d [2] ea 86 [2] e5 9c [2] fb 81 [2] f9 80 [2] e2 86 [2] fe 81 [2] e2 ae }

  condition:
    any of them
}