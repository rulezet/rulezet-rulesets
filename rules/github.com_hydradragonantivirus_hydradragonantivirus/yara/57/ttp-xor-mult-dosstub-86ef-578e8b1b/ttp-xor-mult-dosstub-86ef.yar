rule TTP_XOR_MULT_DOSStub_86ef {
  strings:
    $key_86ef = { d2 87 [2] a6 9f [2] e1 9d [2] a6 8c [2] e8 80 [2] e4 8a [2] f3 81 [2] e8 cf [2] d5 }

  condition:
    any of them
}