rule TTP_XOR_MULT_DOSStub_830a {
  strings:
    $key_830a = { d7 62 [2] a3 7a [2] e4 78 [2] a3 69 [2] ed 65 [2] e1 6f [2] f6 64 [2] ed 2a [2] d0 }

  condition:
    any of them
}