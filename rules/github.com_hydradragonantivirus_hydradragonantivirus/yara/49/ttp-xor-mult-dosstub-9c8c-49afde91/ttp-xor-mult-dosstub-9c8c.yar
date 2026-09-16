rule TTP_XOR_MULT_DOSStub_9c8c {
  strings:
    $key_9c8c = { c8 e4 [2] bc fc [2] fb fe [2] bc ef [2] f2 e3 [2] fe e9 [2] e9 e2 [2] f2 ac [2] cf }

  condition:
    any of them
}