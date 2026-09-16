rule TTP_XOR_MULT_DOSStub_d21c {
  strings:
    $key_d21c = { 86 74 [2] f2 6c [2] b5 6e [2] f2 7f [2] bc 73 [2] b0 79 [2] a7 72 [2] bc 3c [2] 81 }

  condition:
    any of them
}