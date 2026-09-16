rule TTP_XOR_MULT_DOSStub_0249 {
  strings:
    $key_0249 = { 56 21 [2] 22 39 [2] 65 3b [2] 22 2a [2] 6c 26 [2] 60 2c [2] 77 27 [2] 6c 69 [2] 51 }

  condition:
    any of them
}