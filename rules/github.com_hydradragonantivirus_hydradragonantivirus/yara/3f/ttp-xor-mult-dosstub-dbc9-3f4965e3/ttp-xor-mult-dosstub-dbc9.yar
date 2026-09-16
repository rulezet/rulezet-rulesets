rule TTP_XOR_MULT_DOSStub_dbc9 {
  strings:
    $key_dbc9 = { 8f a1 [2] fb b9 [2] bc bb [2] fb aa [2] b5 a6 [2] b9 ac [2] ae a7 [2] b5 e9 [2] 88 }

  condition:
    any of them
}