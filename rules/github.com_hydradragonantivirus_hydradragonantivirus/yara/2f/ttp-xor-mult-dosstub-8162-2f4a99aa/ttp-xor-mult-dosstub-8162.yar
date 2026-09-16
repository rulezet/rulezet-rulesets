rule TTP_XOR_MULT_DOSStub_8162 {
  strings:
    $key_8162 = { d5 0a [2] a1 12 [2] e6 10 [2] a1 01 [2] ef 0d [2] e3 07 [2] f4 0c [2] ef 42 [2] d2 }

  condition:
    any of them
}