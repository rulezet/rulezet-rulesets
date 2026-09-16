rule TTP_XOR_MULT_DOSStub_de1d {
  strings:
    $key_de1d = { 8a 75 [2] fe 6d [2] b9 6f [2] fe 7e [2] b0 72 [2] bc 78 [2] ab 73 [2] b0 3d [2] 8d }

  condition:
    any of them
}