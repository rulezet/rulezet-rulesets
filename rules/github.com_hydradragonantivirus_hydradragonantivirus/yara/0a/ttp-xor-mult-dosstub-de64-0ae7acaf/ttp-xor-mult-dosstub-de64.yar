rule TTP_XOR_MULT_DOSStub_de64 {
  strings:
    $key_de64 = { 8a 0c [2] fe 14 [2] b9 16 [2] fe 07 [2] b0 0b [2] bc 01 [2] ab 0a [2] b0 44 [2] 8d }

  condition:
    any of them
}