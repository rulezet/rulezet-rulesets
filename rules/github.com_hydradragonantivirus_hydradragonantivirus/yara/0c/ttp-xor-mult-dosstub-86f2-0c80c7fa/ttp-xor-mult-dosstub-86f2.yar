rule TTP_XOR_MULT_DOSStub_86f2 {
  strings:
    $key_86f2 = { d2 9a [2] a6 82 [2] e1 80 [2] a6 91 [2] e8 9d [2] e4 97 [2] f3 9c [2] e8 d2 [2] d5 }

  condition:
    any of them
}