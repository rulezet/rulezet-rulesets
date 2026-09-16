rule TTP_XOR_MULT_DOSStub_def3 {
  strings:
    $key_def3 = { 8a 9b [2] fe 83 [2] b9 81 [2] fe 90 [2] b0 9c [2] bc 96 [2] ab 9d [2] b0 d3 [2] 8d }

  condition:
    any of them
}