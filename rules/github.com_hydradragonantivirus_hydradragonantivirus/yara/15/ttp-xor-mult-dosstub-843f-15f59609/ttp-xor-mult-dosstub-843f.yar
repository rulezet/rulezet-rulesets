rule TTP_XOR_MULT_DOSStub_843f {
  strings:
    $key_843f = { d0 57 [2] a4 4f [2] e3 4d [2] a4 5c [2] ea 50 [2] e6 5a [2] f1 51 [2] ea 1f [2] d7 }

  condition:
    any of them
}