rule TTP_XOR_MULT_DOSStub_4157 {
  strings:
    $key_4157 = { 15 3f [2] 61 27 [2] 26 25 [2] 61 34 [2] 2f 38 [2] 23 32 [2] 34 39 [2] 2f 77 [2] 12 }

  condition:
    any of them
}