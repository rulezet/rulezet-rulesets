rule TTP_XOR_MULT_DOSStub_de3e {
  strings:
    $key_de3e = { 8a 56 [2] fe 4e [2] b9 4c [2] fe 5d [2] b0 51 [2] bc 5b [2] ab 50 [2] b0 1e [2] 8d }

  condition:
    any of them
}