rule TTP_XOR_MULT_DOSStub_833f {
  strings:
    $key_833f = { d7 57 [2] a3 4f [2] e4 4d [2] a3 5c [2] ed 50 [2] e1 5a [2] f6 51 [2] ed 1f [2] d0 }

  condition:
    any of them
}