rule TTP_XOR_MULT_DOSStub_dbc0 {
  strings:
    $key_dbc0 = { 8f a8 [2] fb b0 [2] bc b2 [2] fb a3 [2] b5 af [2] b9 a5 [2] ae ae [2] b5 e0 [2] 88 }

  condition:
    any of them
}