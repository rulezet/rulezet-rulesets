rule TTP_XOR_MULT_DOSStub_837b {
  strings:
    $key_837b = { d7 13 [2] a3 0b [2] e4 09 [2] a3 18 [2] ed 14 [2] e1 1e [2] f6 15 [2] ed 5b [2] d0 }

  condition:
    any of them
}