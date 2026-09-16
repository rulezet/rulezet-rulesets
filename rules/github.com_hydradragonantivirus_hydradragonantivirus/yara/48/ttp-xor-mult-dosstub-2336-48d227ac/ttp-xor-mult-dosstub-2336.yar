rule TTP_XOR_MULT_DOSStub_2336 {
  strings:
    $key_2336 = { 77 5e [2] 03 46 [2] 44 44 [2] 03 55 [2] 4d 59 [2] 41 53 [2] 56 58 [2] 4d 16 [2] 70 }

  condition:
    any of them
}