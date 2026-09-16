rule TTP_XOR_MULT_DOSStub_d20a {
  strings:
    $key_d20a = { 86 62 [2] f2 7a [2] b5 78 [2] f2 69 [2] bc 65 [2] b0 6f [2] a7 64 [2] bc 2a [2] 81 }

  condition:
    any of them
}