rule TTP_XOR_MULT_DOSStub_d2ed {
  strings:
    $key_d2ed = { 86 85 [2] f2 9d [2] b5 9f [2] f2 8e [2] bc 82 [2] b0 88 [2] a7 83 [2] bc cd [2] 81 }

  condition:
    any of them
}