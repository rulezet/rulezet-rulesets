rule TTP_XOR_MULT_DOSStub_de5e {
  strings:
    $key_de5e = { 8a 36 [2] fe 2e [2] b9 2c [2] fe 3d [2] b0 31 [2] bc 3b [2] ab 30 [2] b0 7e [2] 8d }

  condition:
    any of them
}