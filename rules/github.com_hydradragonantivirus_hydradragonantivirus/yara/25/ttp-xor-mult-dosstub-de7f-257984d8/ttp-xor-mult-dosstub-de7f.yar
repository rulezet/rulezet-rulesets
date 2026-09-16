rule TTP_XOR_MULT_DOSStub_de7f {
  strings:
    $key_de7f = { 8a 17 [2] fe 0f [2] b9 0d [2] fe 1c [2] b0 10 [2] bc 1a [2] ab 11 [2] b0 5f [2] 8d }

  condition:
    any of them
}