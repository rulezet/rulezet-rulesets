rule TTP_XOR_MULT_DOSStub_5670 {
  strings:
    $key_5670 = { 02 18 [2] 76 00 [2] 31 02 [2] 76 13 [2] 38 1f [2] 34 15 [2] 23 1e [2] 38 50 [2] 05 }

  condition:
    any of them
}