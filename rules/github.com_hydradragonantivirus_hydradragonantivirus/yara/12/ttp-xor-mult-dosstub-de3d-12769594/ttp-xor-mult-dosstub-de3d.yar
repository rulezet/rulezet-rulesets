rule TTP_XOR_MULT_DOSStub_de3d {
  strings:
    $key_de3d = { 8a 55 [2] fe 4d [2] b9 4f [2] fe 5e [2] b0 52 [2] bc 58 [2] ab 53 [2] b0 1d [2] 8d }

  condition:
    any of them
}