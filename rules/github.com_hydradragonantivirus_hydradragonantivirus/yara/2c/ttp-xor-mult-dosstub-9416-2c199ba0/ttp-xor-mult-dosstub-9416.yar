rule TTP_XOR_MULT_DOSStub_9416 {
  strings:
    $key_9416 = { c0 7e [2] b4 66 [2] f3 64 [2] b4 75 [2] fa 79 [2] f6 73 [2] e1 78 [2] fa 36 [2] c7 }

  condition:
    any of them
}