rule TTP_XOR_MULT_DOSStub_84ef {
  strings:
    $key_84ef = { d0 87 [2] a4 9f [2] e3 9d [2] a4 8c [2] ea 80 [2] e6 8a [2] f1 81 [2] ea cf [2] d7 }

  condition:
    any of them
}