rule TTP_XOR_MULT_DOSStub_de4c {
  strings:
    $key_de4c = { 8a 24 [2] fe 3c [2] b9 3e [2] fe 2f [2] b0 23 [2] bc 29 [2] ab 22 [2] b0 6c [2] 8d }

  condition:
    any of them
}