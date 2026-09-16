rule TTP_XOR_MULT_DOSStub_8d8c {
  strings:
    $key_8d8c = { d9 e4 [2] ad fc [2] ea fe [2] ad ef [2] e3 e3 [2] ef e9 [2] f8 e2 [2] e3 ac [2] de }

  condition:
    any of them
}