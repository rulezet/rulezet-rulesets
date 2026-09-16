rule TTP_XOR_MULT_DOSStub_de57 {
  strings:
    $key_de57 = { 8a 3f [2] fe 27 [2] b9 25 [2] fe 34 [2] b0 38 [2] bc 32 [2] ab 39 [2] b0 77 [2] 8d }

  condition:
    any of them
}