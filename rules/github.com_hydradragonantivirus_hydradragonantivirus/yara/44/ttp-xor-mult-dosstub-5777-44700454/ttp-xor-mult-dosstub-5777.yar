rule TTP_XOR_MULT_DOSStub_5777 {
  strings:
    $key_5777 = { 03 1f [2] 77 07 [2] 30 05 [2] 77 14 [2] 39 18 [2] 35 12 [2] 22 19 [2] 39 57 [2] 04 }

  condition:
    any of them
}