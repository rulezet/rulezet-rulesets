rule TTP_XOR_MULT_DOSStub_d2cb {
  strings:
    $key_d2cb = { 86 a3 [2] f2 bb [2] b5 b9 [2] f2 a8 [2] bc a4 [2] b0 ae [2] a7 a5 [2] bc eb [2] 81 }

  condition:
    any of them
}