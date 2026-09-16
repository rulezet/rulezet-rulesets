rule TTP_XOR_MULT_DOSStub_deb1 {
  strings:
    $key_deb1 = { 8a d9 [2] fe c1 [2] b9 c3 [2] fe d2 [2] b0 de [2] bc d4 [2] ab df [2] b0 91 [2] 8d }

  condition:
    any of them
}