rule TTP_XOR_MULT_DOSStub_86f9 {
  strings:
    $key_86f9 = { d2 91 [2] a6 89 [2] e1 8b [2] a6 9a [2] e8 96 [2] e4 9c [2] f3 97 [2] e8 d9 [2] d5 }

  condition:
    any of them
}