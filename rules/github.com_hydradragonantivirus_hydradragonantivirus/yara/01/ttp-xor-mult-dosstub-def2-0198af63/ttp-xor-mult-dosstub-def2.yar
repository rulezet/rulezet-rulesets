rule TTP_XOR_MULT_DOSStub_def2 {
  strings:
    $key_def2 = { 8a 9a [2] fe 82 [2] b9 80 [2] fe 91 [2] b0 9d [2] bc 97 [2] ab 9c [2] b0 d2 [2] 8d }

  condition:
    any of them
}