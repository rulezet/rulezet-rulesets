rule TTP_XOR_MULT_DOSStub_de2d {
  strings:
    $key_de2d = { 8a 45 [2] fe 5d [2] b9 5f [2] fe 4e [2] b0 42 [2] bc 48 [2] ab 43 [2] b0 0d [2] 8d }

  condition:
    any of them
}