rule TTP_XOR_MULT_DOSStub_de51 {
  strings:
    $key_de51 = { 8a 39 [2] fe 21 [2] b9 23 [2] fe 32 [2] b0 3e [2] bc 34 [2] ab 3f [2] b0 71 [2] 8d }

  condition:
    any of them
}