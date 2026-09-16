rule TTP_XOR_MULT_DOSStub_dee4 {
  strings:
    $key_dee4 = { 8a 8c [2] fe 94 [2] b9 96 [2] fe 87 [2] b0 8b [2] bc 81 [2] ab 8a [2] b0 c4 [2] 8d }

  condition:
    any of them
}