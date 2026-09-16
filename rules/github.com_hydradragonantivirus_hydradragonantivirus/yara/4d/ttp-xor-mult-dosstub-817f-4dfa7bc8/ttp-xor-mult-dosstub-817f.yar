rule TTP_XOR_MULT_DOSStub_817f {
  strings:
    $key_817f = { d5 17 [2] a1 0f [2] e6 0d [2] a1 1c [2] ef 10 [2] e3 1a [2] f4 11 [2] ef 5f [2] d2 }

  condition:
    any of them
}