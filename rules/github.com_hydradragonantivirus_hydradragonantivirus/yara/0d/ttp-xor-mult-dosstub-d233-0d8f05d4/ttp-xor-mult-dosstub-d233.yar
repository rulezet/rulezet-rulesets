rule TTP_XOR_MULT_DOSStub_d233 {
  strings:
    $key_d233 = { 86 5b [2] f2 43 [2] b5 41 [2] f2 50 [2] bc 5c [2] b0 56 [2] a7 5d [2] bc 13 [2] 81 }

  condition:
    any of them
}