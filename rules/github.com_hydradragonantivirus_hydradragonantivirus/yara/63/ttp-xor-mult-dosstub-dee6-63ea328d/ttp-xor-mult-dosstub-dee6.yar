rule TTP_XOR_MULT_DOSStub_dee6 {
  strings:
    $key_dee6 = { 8a 8e [2] fe 96 [2] b9 94 [2] fe 85 [2] b0 89 [2] bc 83 [2] ab 88 [2] b0 c6 [2] 8d }

  condition:
    any of them
}