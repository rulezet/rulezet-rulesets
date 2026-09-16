rule TTP_XOR_MULT_DOSStub_de27 {
  strings:
    $key_de27 = { 8a 4f [2] fe 57 [2] b9 55 [2] fe 44 [2] b0 48 [2] bc 42 [2] ab 49 [2] b0 07 [2] 8d }

  condition:
    any of them
}