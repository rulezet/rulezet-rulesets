rule TTP_XOR_MULT_DOSStub_dedd {
  strings:
    $key_dedd = { 8a b5 [2] fe ad [2] b9 af [2] fe be [2] b0 b2 [2] bc b8 [2] ab b3 [2] b0 fd [2] 8d }

  condition:
    any of them
}