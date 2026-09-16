rule TTP_XOR_MULT_DOSStub_83ef {
  strings:
    $key_83ef = { d7 87 [2] a3 9f [2] e4 9d [2] a3 8c [2] ed 80 [2] e1 8a [2] f6 81 [2] ed cf [2] d0 }

  condition:
    any of them
}