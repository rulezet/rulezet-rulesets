rule TTP_XOR_MULT_DOSStub_def4 {
  strings:
    $key_def4 = { 8a 9c [2] fe 84 [2] b9 86 [2] fe 97 [2] b0 9b [2] bc 91 [2] ab 9a [2] b0 d4 [2] 8d }

  condition:
    any of them
}