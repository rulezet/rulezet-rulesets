rule TTP_XOR_MULT_DOSStub_d227 {
  strings:
    $key_d227 = { 86 4f [2] f2 57 [2] b5 55 [2] f2 44 [2] bc 48 [2] b0 42 [2] a7 49 [2] bc 07 [2] 81 }

  condition:
    any of them
}