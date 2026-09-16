rule TTP_XOR_MULT_DOSStub_de2c {
  strings:
    $key_de2c = { 8a 44 [2] fe 5c [2] b9 5e [2] fe 4f [2] b0 43 [2] bc 49 [2] ab 42 [2] b0 0c [2] 8d }

  condition:
    any of them
}