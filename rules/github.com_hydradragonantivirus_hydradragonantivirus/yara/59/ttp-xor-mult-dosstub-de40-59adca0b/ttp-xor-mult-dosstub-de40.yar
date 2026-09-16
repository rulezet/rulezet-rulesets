rule TTP_XOR_MULT_DOSStub_de40 {
  strings:
    $key_de40 = { 8a 28 [2] fe 30 [2] b9 32 [2] fe 23 [2] b0 2f [2] bc 25 [2] ab 2e [2] b0 60 [2] 8d }

  condition:
    any of them
}