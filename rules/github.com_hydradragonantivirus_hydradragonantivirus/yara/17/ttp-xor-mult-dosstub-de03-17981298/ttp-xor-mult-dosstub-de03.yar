rule TTP_XOR_MULT_DOSStub_de03 {
  strings:
    $key_de03 = { 8a 6b [2] fe 73 [2] b9 71 [2] fe 60 [2] b0 6c [2] bc 66 [2] ab 6d [2] b0 23 [2] 8d }

  condition:
    any of them
}