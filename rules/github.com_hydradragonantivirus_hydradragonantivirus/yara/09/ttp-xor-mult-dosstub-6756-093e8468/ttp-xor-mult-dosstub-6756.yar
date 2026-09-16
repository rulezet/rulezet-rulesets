rule TTP_XOR_MULT_DOSStub_6756 {
  strings:
    $key_6756 = { 33 3e [2] 47 26 [2] 00 24 [2] 47 35 [2] 09 39 [2] 05 33 [2] 12 38 [2] 09 76 [2] 34 }

  condition:
    any of them
}