rule TTP_XOR_MULT_DOSStub_d26b {
  strings:
    $key_d26b = { 86 03 [2] f2 1b [2] b5 19 [2] f2 08 [2] bc 04 [2] b0 0e [2] a7 05 [2] bc 4b [2] 81 }

  condition:
    any of them
}