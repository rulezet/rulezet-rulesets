rule TTP_XOR_MULT_DOSStub_d23c {
  strings:
    $key_d23c = { 86 54 [2] f2 4c [2] b5 4e [2] f2 5f [2] bc 53 [2] b0 59 [2] a7 52 [2] bc 1c [2] 81 }

  condition:
    any of them
}