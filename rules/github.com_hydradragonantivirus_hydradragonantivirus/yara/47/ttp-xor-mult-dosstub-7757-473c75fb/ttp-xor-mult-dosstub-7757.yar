rule TTP_XOR_MULT_DOSStub_7757 {
  strings:
    $key_7757 = { 23 3f [2] 57 27 [2] 10 25 [2] 57 34 [2] 19 38 [2] 15 32 [2] 02 39 [2] 19 77 [2] 24 }

  condition:
    any of them
}