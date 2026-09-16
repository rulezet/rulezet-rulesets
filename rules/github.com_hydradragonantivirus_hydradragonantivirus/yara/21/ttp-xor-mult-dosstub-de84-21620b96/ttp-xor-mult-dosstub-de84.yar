rule TTP_XOR_MULT_DOSStub_de84 {
  strings:
    $key_de84 = { 8a ec [2] fe f4 [2] b9 f6 [2] fe e7 [2] b0 eb [2] bc e1 [2] ab ea [2] b0 a4 [2] 8d }

  condition:
    any of them
}