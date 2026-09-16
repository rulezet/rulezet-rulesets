rule TTP_XOR_MULT_DOSStub_de4d {
  strings:
    $key_de4d = { 8a 25 [2] fe 3d [2] b9 3f [2] fe 2e [2] b0 22 [2] bc 28 [2] ab 23 [2] b0 6d [2] 8d }

  condition:
    any of them
}