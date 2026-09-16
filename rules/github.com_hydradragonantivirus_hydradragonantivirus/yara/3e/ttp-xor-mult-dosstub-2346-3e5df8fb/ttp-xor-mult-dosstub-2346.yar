rule TTP_XOR_MULT_DOSStub_2346 {
  strings:
    $key_2346 = { 77 2e [2] 03 36 [2] 44 34 [2] 03 25 [2] 4d 29 [2] 41 23 [2] 56 28 [2] 4d 66 [2] 70 }

  condition:
    any of them
}