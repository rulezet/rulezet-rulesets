rule TTP_XOR_MULT_DOSStub_def6 {
  strings:
    $key_def6 = { 8a 9e [2] fe 86 [2] b9 84 [2] fe 95 [2] b0 99 [2] bc 93 [2] ab 98 [2] b0 d6 [2] 8d }

  condition:
    any of them
}