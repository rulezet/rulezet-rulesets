rule TTP_XOR_MULT_DOSStub_837d {
  strings:
    $key_837d = { d7 15 [2] a3 0d [2] e4 0f [2] a3 1e [2] ed 12 [2] e1 18 [2] f6 13 [2] ed 5d [2] d0 }

  condition:
    any of them
}