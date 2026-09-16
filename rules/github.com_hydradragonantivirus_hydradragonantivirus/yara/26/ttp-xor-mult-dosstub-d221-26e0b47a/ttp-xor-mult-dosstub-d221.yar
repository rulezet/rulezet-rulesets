rule TTP_XOR_MULT_DOSStub_d221 {
  strings:
    $key_d221 = { 86 49 [2] f2 51 [2] b5 53 [2] f2 42 [2] bc 4e [2] b0 44 [2] a7 4f [2] bc 01 [2] 81 }

  condition:
    any of them
}