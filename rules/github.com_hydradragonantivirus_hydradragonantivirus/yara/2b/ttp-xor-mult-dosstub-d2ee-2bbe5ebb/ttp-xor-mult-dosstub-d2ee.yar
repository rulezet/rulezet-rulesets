rule TTP_XOR_MULT_DOSStub_d2ee {
  strings:
    $key_d2ee = { 86 86 [2] f2 9e [2] b5 9c [2] f2 8d [2] bc 81 [2] b0 8b [2] a7 80 [2] bc ce [2] 81 }

  condition:
    any of them
}