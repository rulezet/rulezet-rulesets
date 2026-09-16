rule TTP_XOR_MULT_DOSStub_2347 {
  strings:
    $key_2347 = { 77 2f [2] 03 37 [2] 44 35 [2] 03 24 [2] 4d 28 [2] 41 22 [2] 56 29 [2] 4d 67 [2] 70 }

  condition:
    any of them
}