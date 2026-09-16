rule TTP_XOR_MULT_DOSStub_845f {
  strings:
    $key_845f = { d0 37 [2] a4 2f [2] e3 2d [2] a4 3c [2] ea 30 [2] e6 3a [2] f1 31 [2] ea 7f [2] d7 }

  condition:
    any of them
}