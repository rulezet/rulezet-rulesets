rule TTP_XOR_MULT_DOSStub_dbb1 {
  strings:
    $key_dbb1 = { 8f d9 [2] fb c1 [2] bc c3 [2] fb d2 [2] b5 de [2] b9 d4 [2] ae df [2] b5 91 [2] 88 }

  condition:
    any of them
}