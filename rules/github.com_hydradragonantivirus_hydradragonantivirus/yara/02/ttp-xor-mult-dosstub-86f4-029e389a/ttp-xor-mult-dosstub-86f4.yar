rule TTP_XOR_MULT_DOSStub_86f4 {
  strings:
    $key_86f4 = { d2 9c [2] a6 84 [2] e1 86 [2] a6 97 [2] e8 9b [2] e4 91 [2] f3 9a [2] e8 d4 [2] d5 }

  condition:
    any of them
}