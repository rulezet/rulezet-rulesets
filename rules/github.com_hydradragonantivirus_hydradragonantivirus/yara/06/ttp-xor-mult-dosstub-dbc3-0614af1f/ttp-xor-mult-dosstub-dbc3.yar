rule TTP_XOR_MULT_DOSStub_dbc3 {
  strings:
    $key_dbc3 = { 8f ab [2] fb b3 [2] bc b1 [2] fb a0 [2] b5 ac [2] b9 a6 [2] ae ad [2] b5 e3 [2] 88 }

  condition:
    any of them
}