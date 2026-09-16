rule TTP_XOR_MULT_DOSStub_d216 {
  strings:
    $key_d216 = { 86 7e [2] f2 66 [2] b5 64 [2] f2 75 [2] bc 79 [2] b0 73 [2] a7 78 [2] bc 36 [2] 81 }

  condition:
    any of them
}