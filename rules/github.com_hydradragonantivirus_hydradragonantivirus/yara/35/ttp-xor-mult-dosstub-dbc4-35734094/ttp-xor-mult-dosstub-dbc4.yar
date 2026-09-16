rule TTP_XOR_MULT_DOSStub_dbc4 {
  strings:
    $key_dbc4 = { 8f ac [2] fb b4 [2] bc b6 [2] fb a7 [2] b5 ab [2] b9 a1 [2] ae aa [2] b5 e4 [2] 88 }

  condition:
    any of them
}