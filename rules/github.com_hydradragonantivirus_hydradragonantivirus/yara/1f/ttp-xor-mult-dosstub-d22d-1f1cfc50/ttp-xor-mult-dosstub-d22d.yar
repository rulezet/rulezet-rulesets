rule TTP_XOR_MULT_DOSStub_d22d {
  strings:
    $key_d22d = { 86 45 [2] f2 5d [2] b5 5f [2] f2 4e [2] bc 42 [2] b0 48 [2] a7 43 [2] bc 0d [2] 81 }

  condition:
    any of them
}