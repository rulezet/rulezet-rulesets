rule TTP_XOR_MULT_DOSStub_d271 {
  strings:
    $key_d271 = { 86 19 [2] f2 01 [2] b5 03 [2] f2 12 [2] bc 1e [2] b0 14 [2] a7 1f [2] bc 51 [2] 81 }

  condition:
    any of them
}