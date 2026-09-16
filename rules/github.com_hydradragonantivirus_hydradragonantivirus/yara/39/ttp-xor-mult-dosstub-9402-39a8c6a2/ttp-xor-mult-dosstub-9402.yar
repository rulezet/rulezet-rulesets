rule TTP_XOR_MULT_DOSStub_9402 {
  strings:
    $key_9402 = { c0 6a [2] b4 72 [2] f3 70 [2] b4 61 [2] fa 6d [2] f6 67 [2] e1 6c [2] fa 22 [2] c7 }

  condition:
    any of them
}