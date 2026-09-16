rule TTP_XOR_MULT_DOSStub_de5f {
  strings:
    $key_de5f = { 8a 37 [2] fe 2f [2] b9 2d [2] fe 3c [2] b0 30 [2] bc 3a [2] ab 31 [2] b0 7f [2] 8d }

  condition:
    any of them
}