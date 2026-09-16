rule TTP_XOR_MULT_DOSStub_dbc7 {
  strings:
    $key_dbc7 = { 8f af [2] fb b7 [2] bc b5 [2] fb a4 [2] b5 a8 [2] b9 a2 [2] ae a9 [2] b5 e7 [2] 88 }

  condition:
    any of them
}