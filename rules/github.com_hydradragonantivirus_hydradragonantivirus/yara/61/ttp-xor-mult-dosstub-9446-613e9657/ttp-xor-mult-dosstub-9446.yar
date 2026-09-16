rule TTP_XOR_MULT_DOSStub_9446 {
  strings:
    $key_9446 = { c0 2e [2] b4 36 [2] f3 34 [2] b4 25 [2] fa 29 [2] f6 23 [2] e1 28 [2] fa 66 [2] c7 }

  condition:
    any of them
}