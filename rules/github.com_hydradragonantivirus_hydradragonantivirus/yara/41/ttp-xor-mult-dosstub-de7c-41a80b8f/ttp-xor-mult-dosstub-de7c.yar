rule TTP_XOR_MULT_DOSStub_de7c {
  strings:
    $key_de7c = { 8a 14 [2] fe 0c [2] b9 0e [2] fe 1f [2] b0 13 [2] bc 19 [2] ab 12 [2] b0 5c [2] 8d }

  condition:
    any of them
}