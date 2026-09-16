rule TTP_XOR_MULT_DOSStub_837a {
  strings:
    $key_837a = { d7 12 [2] a3 0a [2] e4 08 [2] a3 19 [2] ed 15 [2] e1 1f [2] f6 14 [2] ed 5a [2] d0 }

  condition:
    any of them
}