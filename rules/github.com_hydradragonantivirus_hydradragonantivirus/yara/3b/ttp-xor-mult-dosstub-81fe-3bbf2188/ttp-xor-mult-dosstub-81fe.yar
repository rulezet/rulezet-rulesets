rule TTP_XOR_MULT_DOSStub_81fe {
  strings:
    $key_81fe = { d5 96 [2] a1 8e [2] e6 8c [2] a1 9d [2] ef 91 [2] e3 9b [2] f4 90 [2] ef de [2] d2 }

  condition:
    any of them
}