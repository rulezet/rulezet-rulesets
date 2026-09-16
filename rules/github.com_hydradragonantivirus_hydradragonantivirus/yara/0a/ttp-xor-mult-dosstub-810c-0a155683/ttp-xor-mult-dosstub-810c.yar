rule TTP_XOR_MULT_DOSStub_810c {
  strings:
    $key_810c = { d5 64 [2] a1 7c [2] e6 7e [2] a1 6f [2] ef 63 [2] e3 69 [2] f4 62 [2] ef 2c [2] d2 }

  condition:
    any of them
}