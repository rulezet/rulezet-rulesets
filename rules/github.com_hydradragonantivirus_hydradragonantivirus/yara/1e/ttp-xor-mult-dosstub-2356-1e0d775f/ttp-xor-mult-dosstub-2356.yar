rule TTP_XOR_MULT_DOSStub_2356 {
  strings:
    $key_2356 = { 77 3e [2] 03 26 [2] 44 24 [2] 03 35 [2] 4d 39 [2] 41 33 [2] 56 38 [2] 4d 76 [2] 70 }

  condition:
    any of them
}