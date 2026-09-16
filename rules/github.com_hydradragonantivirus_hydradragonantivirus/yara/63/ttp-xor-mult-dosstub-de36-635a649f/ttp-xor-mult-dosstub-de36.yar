rule TTP_XOR_MULT_DOSStub_de36 {
  strings:
    $key_de36 = { 8a 5e [2] fe 46 [2] b9 44 [2] fe 55 [2] b0 59 [2] bc 53 [2] ab 58 [2] b0 16 [2] 8d }

  condition:
    any of them
}