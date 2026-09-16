rule TTP_XOR_MULT_DOSStub_de7a {
  strings:
    $key_de7a = { 8a 12 [2] fe 0a [2] b9 08 [2] fe 19 [2] b0 15 [2] bc 1f [2] ab 14 [2] b0 5a [2] 8d }

  condition:
    any of them
}