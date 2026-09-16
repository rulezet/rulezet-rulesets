rule TTP_XOR_MULT_DOSStub_94f1 {
  strings:
    $key_94f1 = { c0 99 [2] b4 81 [2] f3 83 [2] b4 92 [2] fa 9e [2] f6 94 [2] e1 9f [2] fa d1 [2] c7 }

  condition:
    any of them
}