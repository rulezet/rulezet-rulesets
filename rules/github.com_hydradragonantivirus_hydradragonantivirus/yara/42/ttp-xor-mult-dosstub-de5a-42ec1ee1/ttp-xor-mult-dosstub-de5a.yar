rule TTP_XOR_MULT_DOSStub_de5a {
  strings:
    $key_de5a = { 8a 32 [2] fe 2a [2] b9 28 [2] fe 39 [2] b0 35 [2] bc 3f [2] ab 34 [2] b0 7a [2] 8d }

  condition:
    any of them
}