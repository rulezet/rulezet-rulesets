rule TTP_XOR_MULT_DOSStub_81e5 {
  strings:
    $key_81e5 = { d5 8d [2] a1 95 [2] e6 97 [2] a1 86 [2] ef 8a [2] e3 80 [2] f4 8b [2] ef c5 [2] d2 }

  condition:
    any of them
}