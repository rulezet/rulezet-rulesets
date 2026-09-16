rule TTP_XOR_MULT_DOSStub_def7 {
  strings:
    $key_def7 = { 8a 9f [2] fe 87 [2] b9 85 [2] fe 94 [2] b0 98 [2] bc 92 [2] ab 99 [2] b0 d7 [2] 8d }

  condition:
    any of them
}