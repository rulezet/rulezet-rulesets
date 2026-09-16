rule TTP_XOR_MULT_DOSStub_86e3 {
  strings:
    $key_86e3 = { d2 8b [2] a6 93 [2] e1 91 [2] a6 80 [2] e8 8c [2] e4 86 [2] f3 8d [2] e8 c3 [2] d5 }

  condition:
    any of them
}