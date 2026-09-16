rule TTP_XOR_MULT_DOSStub_8c8c {
  strings:
    $key_8c8c = { d8 e4 [2] ac fc [2] eb fe [2] ac ef [2] e2 e3 [2] ee e9 [2] f9 e2 [2] e2 ac [2] df }

  condition:
    any of them
}