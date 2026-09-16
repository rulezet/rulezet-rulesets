rule TTP_XOR_MULT_DOSStub_d237 {
  strings:
    $key_d237 = { 86 5f [2] f2 47 [2] b5 45 [2] f2 54 [2] bc 58 [2] b0 52 [2] a7 59 [2] bc 17 [2] 81 }

  condition:
    any of them
}