rule TTP_XOR_MULT_DOSStub_de1a {
  strings:
    $key_de1a = { 8a 72 [2] fe 6a [2] b9 68 [2] fe 79 [2] b0 75 [2] bc 7f [2] ab 74 [2] b0 3a [2] 8d }

  condition:
    any of them
}