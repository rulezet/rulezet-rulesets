rule TTP_XOR_MULT_DOSStub_847f {
  strings:
    $key_847f = { d0 17 [2] a4 0f [2] e3 0d [2] a4 1c [2] ea 10 [2] e6 1a [2] f1 11 [2] ea 5f [2] d7 }

  condition:
    any of them
}