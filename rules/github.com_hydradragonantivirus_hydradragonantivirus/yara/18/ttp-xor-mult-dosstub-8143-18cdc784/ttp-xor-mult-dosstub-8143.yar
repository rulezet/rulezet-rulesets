rule TTP_XOR_MULT_DOSStub_8143 {
  strings:
    $key_8143 = { d5 2b [2] a1 33 [2] e6 31 [2] a1 20 [2] ef 2c [2] e3 26 [2] f4 2d [2] ef 63 [2] d2 }

  condition:
    any of them
}