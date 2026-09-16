rule TTP_XOR_MULT_DOSStub_6771 {
  strings:
    $key_6771 = { 33 19 [2] 47 01 [2] 00 03 [2] 47 12 [2] 09 1e [2] 05 14 [2] 12 1f [2] 09 51 [2] 34 }

  condition:
    any of them
}