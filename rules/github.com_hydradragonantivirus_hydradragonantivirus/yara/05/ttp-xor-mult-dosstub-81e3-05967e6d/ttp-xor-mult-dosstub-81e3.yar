rule TTP_XOR_MULT_DOSStub_81e3 {
  strings:
    $key_81e3 = { d5 8b [2] a1 93 [2] e6 91 [2] a1 80 [2] ef 8c [2] e3 86 [2] f4 8d [2] ef c3 [2] d2 }

  condition:
    any of them
}