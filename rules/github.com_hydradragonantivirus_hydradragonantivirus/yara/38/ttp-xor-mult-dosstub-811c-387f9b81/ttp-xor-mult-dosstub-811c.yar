rule TTP_XOR_MULT_DOSStub_811c {
  strings:
    $key_811c = { d5 74 [2] a1 6c [2] e6 6e [2] a1 7f [2] ef 73 [2] e3 79 [2] f4 72 [2] ef 3c [2] d2 }

  condition:
    any of them
}