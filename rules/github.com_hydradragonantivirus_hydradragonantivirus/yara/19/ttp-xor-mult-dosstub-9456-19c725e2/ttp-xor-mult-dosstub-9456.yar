rule TTP_XOR_MULT_DOSStub_9456 {
  strings:
    $key_9456 = { c0 3e [2] b4 26 [2] f3 24 [2] b4 35 [2] fa 39 [2] f6 33 [2] e1 38 [2] fa 76 [2] c7 }

  condition:
    any of them
}