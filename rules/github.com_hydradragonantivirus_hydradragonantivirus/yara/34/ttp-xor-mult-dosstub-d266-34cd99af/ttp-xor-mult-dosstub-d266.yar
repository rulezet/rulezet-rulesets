rule TTP_XOR_MULT_DOSStub_d266 {
  strings:
    $key_d266 = { 86 0e [2] f2 16 [2] b5 14 [2] f2 05 [2] bc 09 [2] b0 03 [2] a7 08 [2] bc 46 [2] 81 }

  condition:
    any of them
}