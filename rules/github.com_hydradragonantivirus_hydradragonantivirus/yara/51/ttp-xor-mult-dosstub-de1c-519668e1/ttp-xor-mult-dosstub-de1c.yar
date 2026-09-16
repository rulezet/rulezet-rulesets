rule TTP_XOR_MULT_DOSStub_de1c {
  strings:
    $key_de1c = { 8a 74 [2] fe 6c [2] b9 6e [2] fe 7f [2] b0 73 [2] bc 79 [2] ab 72 [2] b0 3c [2] 8d }

  condition:
    any of them
}